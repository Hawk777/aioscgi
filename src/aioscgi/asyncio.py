"""An I/O adapter connecting aioscgi to the Python standard library asyncio."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import io
import logging
import pathlib
import signal
import socket
import sys
from collections.abc import AsyncIterable, Awaitable, Callable, Iterable
from contextlib import AbstractAsyncContextManager
from typing import Self

from . import http, lifespan
from .container import Container
from .tcp import TCPAddress
from .types import StartStopListener


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

    def create_mutex(self: Self) -> AbstractAsyncContextManager[None]:  # noqa: D102
        return asyncio.Lock()

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
        "_connection_tasks",
        "_container",
    }

    _connection_tasks: set[asyncio.Task[None]]
    _container: Container

    def __init__(self: Self, container: Container) -> None:
        """
        Construct a new ConnectionHandler.

        :param container: The ASGI container.
        """
        self._connection_tasks = set()
        self._container = container

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
    start_server_fn: Callable[
        [Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]],
        Awaitable[list[asyncio.Server]],
    ],
    container: Container,
    listener: StartStopListener,
) -> None:
    """
    Run the application in an asyncio event loop.

    :param application: The application callable.
    :param start_server_fn: A function which accepts a connection handler and starts and
        returns one or more servers.
    :param container: The ASGI container to use.
    :param listener: The start/stop listener to notify of startup/shutdown.
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

            # Start the server.
            servers = await start_server_fn(connection_handler.handle_connection)
            logging.getLogger(__name__).info("Server up and running")

            # Notify the listener.
            listener.started()

            # Wait until requested to terminate.
            signal_name = await term_sig
            logging.getLogger(__name__).info(
                "Caught termination signal %s", signal_name
            )

            # Notify the listener.
            listener.stopping()

            # Close the listening sockets.
            for server in servers:
                server.close()
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
            for server in servers:
                await server.wait_closed()
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
                except Exception:  # pylint: disable=broad-except
                    logging.getLogger(__name__).exception(
                        "Uncaught exception while cancelling task",
                    )


async def _start_servers_gen(
    tcp_addresses: Iterable[TCPAddress],
    unix_paths: Iterable[pathlib.Path],
    extra_sockets: Iterable[socket.socket],
    handle_connection: Callable[
        [asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]
    ],
) -> AsyncIterable[asyncio.Server]:
    """
    Start a collection of TCP and UNIX-domain servers.

    The UNIX-domain paths are chmodded to mode 666.

    The servers are started lazily as the returned iterable is iterated.

    :param tcp_addresses: The TCP addresses to listen on.
    :param unix_paths: The UNIX-domain socket filenames to listen on.
    :param extra_sockets: The extra already-bound sockets on which to listen.
    :param handle_connection: The connection handler to pass into the created asyncio
        servers.
    :return: The started servers.
    """
    # Python 3.13 added the cleanup_socket parameter to create_unix_server (and, albeit
    # undocumented, therefore to start_unix_server as well), and defaulted it to True,
    # which is bad for sockets passed in from an outside source.
    if sys.hexversion >= 0x030D00F0:

        async def start_unix_server_from_socket(sock: socket.socket) -> asyncio.Server:
            return await asyncio.start_unix_server(
                handle_connection,
                sock=sock,
                cleanup_socket=False,
            )
    else:

        async def start_unix_server_from_socket(sock: socket.socket) -> asyncio.Server:
            return await asyncio.start_unix_server(
                handle_connection,
                sock=sock,
            )

    for extra_socket in extra_sockets:
        if extra_socket.type != socket.SOCK_STREAM:
            msg = f"External socket is type {extra_socket.type}, SOCK_STREAM required"
            raise ValueError(msg)
        if extra_socket.family in (socket.AF_INET, socket.AF_INET6):
            yield await asyncio.start_server(handle_connection, sock=extra_socket)
        elif extra_socket.family == socket.AF_UNIX:
            yield await start_unix_server_from_socket(extra_socket)
        else:
            msg = f"Unrecognized external socket family {extra_socket.family}"
            raise ValueError(msg)
    for tcp_address in tcp_addresses:
        yield await asyncio.start_server(
            handle_connection, host=tcp_address.host, port=tcp_address.port
        )
    for unix_path in unix_paths:
        server = await asyncio.start_unix_server(handle_connection, path=unix_path)
        unix_path.chmod(0o666)
        yield server


async def _start_servers(
    tcp_addresses: Iterable[TCPAddress],
    unix_paths: Iterable[pathlib.Path],
    extra_sockets: Iterable[socket.socket],
    handle_connection: Callable[
        [asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]
    ],
) -> list[asyncio.Server]:
    """
    Start a collection of TCP and UNIX-domain servers.

    The UNIX-domain paths are chmodded to mode 666.

    :param tcp_addresses: The TCP addresses to listen on.
    :param unix_paths: The UNIX-domain socket filenames to listen on.
    :param extra_sockets: The extra already-bound sockets on which to listen.
    :param handle_connection: The connection handler to pass into the created asyncio
        servers.
    :return: The started servers.
    """
    with contextlib.ExitStack() as stack:
        servers = [
            stack.enter_context(contextlib.closing(i))
            async for i in _start_servers_gen(
                tcp_addresses, unix_paths, extra_sockets, handle_connection
            )
        ]
        stack.pop_all()
    return servers


def run(
    tcp_addresses: Iterable[TCPAddress],
    unix_paths: Iterable[pathlib.Path],
    extra_sockets: Iterable[socket.socket],
    container: Container,
    listener: StartStopListener,
) -> None:
    """
    Run an application listening for SCGI connections on one or more TCP/UNIX sockets.

    UNIX sockets always have file mode 666. It is not really possible to create a
    UNIX-domain socket with more restrictive permissions from the outset (other than
    perhaps by using umask, which is not thread-safe), and creating it with a more
    permissive mode and then chmodding it afterward leaves an undesirable race
    condition.

    :param tcp_addresses: The TCP addresses on which to listen.
    :param unix_paths: The UNIX-domain socket filenames on which to listen.
    :param extra_sockets: The extra already-bound sockets on which to listen.
    :param container: The ASGI container to use.
    :param listener: The start/stop listener to notify of startup/shutdown.
    """
    asyncio.run(
        _main_coroutine(
            functools.partial(_start_servers, tcp_addresses, unix_paths, extra_sockets),
            container,
            listener,
        )
    )
