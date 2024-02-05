"""An I/O adapter connecting aioscgi to the Python standard library asyncio."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import io
import logging
import os
import signal
from collections.abc import Awaitable, Callable
from typing import Self

from . import http, lifespan
from .container import Container


def _do_nothing() -> None:
    """Do nothing."""


class Connection(http.Connection):
    """An HTTP connection over asyncio."""

    __slots__ = {
        "_stream_reader": """The stream reader for the connection.""",
        "_stream_writer": """The stream writer for the connection.""",
    }

    _stream_reader: asyncio.StreamReader
    _stream_writer: asyncio.StreamWriter

    def __init__(
        self: Self,
        container: Container,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Construct a new Connection.

        :param container: The ASGI container.
        :param reader: The read half of the connection.
        :param writer: The write half of the connection.
        """
        super().__init__(container)
        self._stream_reader = reader
        self._stream_writer = writer

    async def read_chunk(self: Self) -> bytes:  # noqa: D102
        return await self._stream_reader.read(io.DEFAULT_BUFFER_SIZE)

    async def write_chunk(self: Self, data: bytes, drain: bool) -> None:  # noqa: D102
        self._stream_writer.write(data)
        if drain:
            await self._stream_writer.drain()


class ConnectionHandler:
    """
    A handler for incoming connections.

    This handler handles creating a Connection object for each connection and running
    it, closing the connection once the application callable is finished, and tracking
    the set of running connection-handling tasks.
    """

    __slots__ = {
        "_container",
        "_connection_tasks",
    }

    _container: Container
    _connection_tasks: set[asyncio.Task[None]]

    def __init__(self: Self, container: Container) -> None:
        """
        Construct a new ConnectionHandler.

        :param container: The ASGI container.
        """
        self._container = container
        self._connection_tasks = set()

    async def handle_connection(
        self: Self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle a single connection.

        :param reader: The read half of the connection.
        :param writer: The write half of the connection.
        """
        task = asyncio.current_task()
        assert task is not None
        self._connection_tasks.add(task)
        try:
            try:
                return await Connection(self._container, reader, writer).run()
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            self._connection_tasks.remove(task)

    async def wait_finished(self: Self) -> None:
        """Wait until all connection tasks have completed."""
        while self._connection_tasks:
            await next(iter(self._connection_tasks))


async def _main_coroutine(
    start_server_fn: Callable[..., Awaitable[asyncio.Server]],
    after_listen_cb: Callable[[], None],
    container: Container,
) -> None:
    """
    Run the application in an asyncio event loop.

    :param application: The application callable.
    :param start_server_fn: Either asyncio.start_server or asyncio.start_unix_server,
        with server-type-specific parameters bound via functools.partial.
    :param after_listen_cb: The function to call after the server is up and running.
    :param container: The ASGI container to use.
    """
    # Get the event loop.
    loop = asyncio.get_event_loop()

    # Create a future and arrange for it to be completed whenever SIGINT or SIGTERM is
    # received, if on a platform supporting signals. On other platforms, just create the
    # future but don’t ever set it, which causes an endless wait and non-graceful
    # termination.
    term_sig = loop.create_future()
    if hasattr(loop, "add_signal_handler"):

        def signal_handler(signal_name: str) -> None:
            """Handle a signal."""
            # InvalidStateError is raised if the future has already completed, which it
            # might have if two signals are received.
            with contextlib.suppress(asyncio.InvalidStateError):
                term_sig.set_result(signal_name)

        for signal_name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signal_name):
                loop.add_signal_handler(
                    getattr(signal, signal_name),
                    functools.partial(signal_handler, signal_name),
                )

    # Start up the lifespan protocol.
    lifespan_started = loop.create_future()
    lifespan_shutting_down = loop.create_future()
    lifespan_shutdown_complete = loop.create_future()
    lifespan_manager = lifespan.Manager(
        container,
        loop.create_future(),
        asyncio.Lock(),
        lifespan_started.set_result,
        lifespan_shutting_down,
        lifespan_shutdown_complete.set_result,
    )
    lifespan_future = asyncio.ensure_future(lifespan_manager.run())

    try:
        # Wait for the application to start.
        startup_error = await lifespan_started
        if startup_error is not None:
            logging.getLogger(__name__).error(
                "Application startup failed: %s", startup_error
            )
            return

        try:
            # Create a connection handler.
            connection_handler = ConnectionHandler(container)

            # Start the server and, if provided, run the after listen callback.
            srv = await start_server_fn(connection_handler.handle_connection)
            after_listen_cb()
            logging.getLogger(__name__).info("Server up and running")

            # Wait until requested to terminate.
            signal_name = await term_sig
            logging.getLogger(__name__).info(
                "Caught termination signal %s", signal_name
            )

            # Close the listening socket.
            srv.close()
            logging.getLogger(__name__).info("Server no longer listening")

            # Wait until all the client connections finish. Each time a task finishes,
            # it removes itself from the set, and we want to wait until they are all
            # gone, so just wait for an arbitrary task over and over until the set is
            # empty.
            #
            # In some versions of Python, wait_closed theoretically waits until the
            # closure of the listening socket is complete, but in practice doesn’t
            # actually do anything because the listening socket is closed synchronously.
            # In other versions of Python, wait_closed does that and also waits until
            # all accepted connections have been completed as well. Either way, it’s
            # reasonable to call it and to consider it part of waiting for closure of
            # existing connections.
            await srv.wait_closed()
            await connection_handler.wait_finished()
            logging.getLogger(__name__).info("All client connections closed")
        finally:
            # Shut down the application.
            lifespan_shutting_down.set_result(None)
            shutdown_error = await lifespan_shutdown_complete
            if shutdown_error is not None:
                logging.getLogger(__name__).error(
                    "Application shutdown failed: %s", shutdown_error
                )
            await lifespan_future
    finally:
        # Cancel all the running tasks except myself, thus allowing them to clean up
        # properly.
        logging.getLogger(__name__).debug("Terminating running tasks")
        all_tasks = asyncio.all_tasks(loop)
        for i in all_tasks:
            if not i.done() and i != asyncio.current_task():
                i.cancel()
        for i in all_tasks:
            if not i.done() and i != asyncio.current_task():
                try:
                    await i
                except asyncio.CancelledError:
                    # Nothing to see here. Move along.
                    pass
                except Exception:  # pylint: disable=broad-except # noqa: BLE001
                    logging.getLogger(__name__).error(
                        "Uncaught exception while cancelling task", exc_info=True
                    )


def run_tcp(
    hosts: list[str] | None,
    port: int,
    container: Container,
) -> None:
    """
    Run an application listening for SCGI connections on a TCP port.

    :param hosts: The list of list of hosts to bind to, or None to bind to all
        interfaces.
    :param port: The port number.
    :param container: The ASGI container to use.
    """
    asyncio.run(
        _main_coroutine(
            functools.partial(asyncio.start_server, host=hosts, port=port),
            _do_nothing,
            container,
        )
    )


def run_unix(path: str, container: Container) -> None:
    """
    Run an application listening for SCGI connections on a UNIX socket.

    The socket always has file mode 666. It is not really possible to create a
    UNIX-domain socket with more restrictive permissions from the outset (other than
    perhaps by using umask, which is not thread-safe), and creating it with a more
    permissive mode and then chmodding it afterward leaves an undesirable race
    condition.

    :param path: The filename of the socket to listen on.
    :param container: The ASGI container to use.
    """
    asyncio.run(
        _main_coroutine(
            functools.partial(asyncio.start_unix_server, path=path),
            functools.partial(os.chmod, path, 0o666),
            container,
        )
    )
