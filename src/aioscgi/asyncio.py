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
from typing import override

from . import http, lifespan
from .container import Container
from .tcp import TCPAddress
from .types import StartStopListener


class Connection(http.Connection):
    """An HTTP connection over asyncio."""

    __slots__ = {
        "_stream_reader": "The stream reader for the connection.",
        "_stream_writer": "The stream writer for the connection.",
    }

    _stream_reader: asyncio.StreamReader
    _stream_writer: asyncio.StreamWriter

    def __init__(
        self,
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

    @override
    def create_mutex(self) -> AbstractAsyncContextManager[None]:
        return asyncio.Lock()

    @override
    async def read_chunk(self) -> bytes:
        return await self._stream_reader.read(io.DEFAULT_BUFFER_SIZE)

    @override
    async def write_chunk(self, data: bytes, drain: bool) -> None:
        self._stream_writer.write(data)
        if drain:
            await self._stream_writer.drain()


class _ConnectionHandler:
    """
    A handler for incoming connections.

    This handler handles creating a Connection object for each connection and running
    it, closing the connection once the application callable is finished, and tracking
    the set of running connection-handling tasks.
    """

    __slots__ = {
        "_container": "The ASGI container.",
        "_group": "The task group in which to place connection-handling tasks.",
    }

    _container: Container
    _group: asyncio.TaskGroup

    def __init__(self, container: Container, group: asyncio.TaskGroup) -> None:
        """
        Construct a new _ConnectionHandler.

        :param container: The ASGI container.
        :param group: The task group in which to place connection-handling tasks.
        """
        self._container = container
        self._group = group

    def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle a single connection.

        :param reader: The read half of the connection.
        :param writer: The write half of the connection.
        """
        self._group.create_task(self._handle_connection_async(reader, writer))

    async def _handle_connection_async(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle a single connection, running as a task.

        :param reader: The read half of the connection.
        :param writer: The write half of the connection.
        """
        try:
            return await Connection(self._container, reader, writer).run()
        # We don’t want to crash the whole server, and the exception is being logged.
        # pylint: disable-next=broad-exception-caught
        except Exception:
            logging.getLogger(__name__).exception("Unhandled exception in application")
        finally:
            writer.close()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                await writer.wait_closed()


class _LifespanStartError(Exception):
    """The application reported a startup error via the lifespan protocol."""


class _LifespanStopError(Exception):
    """The application reported a shutdown error via the lifespan protocol."""


class _QuitError(Exception):
    """A fast-shutdown event was received."""

    @staticmethod
    async def raise_on_event(e: asyncio.Event) -> None:
        """Wait for an event to be signalled, then raise _QuitError."""
        await e.wait()
        raise _QuitError


def _complete_lifespan_future(
    fut: asyncio.Future[None],
    typ: type[Exception],
    error: str | None,
) -> None:
    """
    Complete a future used for monitoring progress of the lifespan protocol.

    If :param error: is not None, :param fut: will be completed with an exception.
    Otherwise, it will be completed successfully.

    :param fut: The future to complete.
    :param typ: The type of exception to complete :param fut: with on error.
    :param error: The error message, if an error occurred.
    """
    if error is not None:
        fut.set_exception(typ(error))
    else:
        fut.set_result(None)


def _set_two_events(e1: asyncio.Event, e2: asyncio.Event) -> None:
    """
    Set two event objects to signalled.

    :param e1: The first event.
    :param e2: The second event.
    """
    e1.set()
    e2.set()


async def _main_coroutine(
    start_server_fn: Callable[
        [Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]],
        Awaitable[list[asyncio.Server]],
    ],
    container: Container,
    listener: StartStopListener,
    shutdown_timeout: float,
) -> None:
    """
    Run the application in an asyncio event loop.

    :param start_server_fn: A function which accepts a connection handler and starts and
        returns one or more servers.
    :param container: The ASGI container to use.
    :param listener: The start/stop listener to notify of startup/shutdown.
    :param shutdown_timeout: How long to wait for open connections to finish before
        closing them forcefully.
    """
    # Create the termination event and hook up the signal handlers, if signals are
    # supported.
    loop = asyncio.get_event_loop()
    term_event = asyncio.Event()
    quit_event = asyncio.Event()
    if hasattr(loop, "add_signal_handler"):
        for signal_name in ("SIGINT", "SIGTERM"):
            signal_number = getattr(signal, signal_name, None)
            if signal_number is not None:
                loop.add_signal_handler(signal_number, term_event.set)
        signal_number = getattr(signal, "SIGQUIT", None)
        if signal_number is not None:
            loop.add_signal_handler(
                signal_number,
                _set_two_events,
                term_event,
                quit_event,
            )

    try:
        # Run the server.
        await _main_coroutine_with_events(
            start_server_fn,
            container,
            listener,
            term_event,
            quit_event,
            shutdown_timeout,
        )
    # If a lifespan error occurred, print it, but in its basic form, without a
    # traceback, because the traceback won’t show anything useful.
    except* _LifespanStartError as exp_group:
        # ruff: ignore[TRY400]
        logging.getLogger(__name__).error(
            "Application failed to initialize: %s",
            exp_group.exceptions[0],
        )
    except* _LifespanStopError as exp_group:
        # ruff: ignore[TRY400]
        logging.getLogger(__name__).error(
            "Application failed to shut down: %s",
            exp_group.exceptions[0],
        )
    finally:
        # Cancel all the running tasks except myself, thus allowing them to clean up
        # properly. In a well-written application there shouldn’t be any (the lifetime
        # protocol should have shut them down), but a poorly written application might
        # have left some background tasks running which would otherwise prevent us from
        # shutting down.
        all_tasks = asyncio.all_tasks(loop)
        if len(all_tasks) > 1:  # If it’s just one, it’s ourself!
            logging.getLogger(__name__).warning(
                (
                    "%d background task(s) still running after shutdown. They will be "
                    "cancelled. You should use the lifespan protocol to cleanly shut "
                    "them down instead."
                ),
                len(all_tasks),
            )
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


async def _main_coroutine_with_events(
    start_server_fn: Callable[
        [Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]],
        Awaitable[list[asyncio.Server]],
    ],
    container: Container,
    listener: StartStopListener,
    term_event: asyncio.Event,
    quit_event: asyncio.Event,
    shutdown_timeout: float,
) -> None:
    """
    Run the application in an asyncio event loop with a termination event.

    :param start_server_fn: A function which accepts a connection handler and starts and
        returns one or more servers.
    :param container: The ASGI container to use.
    :param listener: The start/stop listener to notify of startup/shutdown.
    :param term_event: An event that is set when the server should shut down.
    :param quit_event: An event that is set when the server should shut down fast.
    :param shutdown_timeout: How long to wait for open connections to finish before
        closing them forcefully.

    :raise _LifespanStartError: If the application fails to initialize.
    :raise _LifespanStopError: If the application fails to shut down.
    """
    async with asyncio.TaskGroup() as lifespan_tg:
        # Start up the lifespan protocol.
        loop = asyncio.get_event_loop()
        lifespan_started = loop.create_future()
        lifespan_shutting_down = loop.create_future()
        lifespan_shutdown_complete = loop.create_future()
        lifespan_manager = lifespan.Manager(
            container,
            loop.create_future(),
            asyncio.Lock(),
            functools.partial(
                _complete_lifespan_future,
                lifespan_started,
                _LifespanStartError,
            ),
            lifespan_shutting_down,
            functools.partial(
                _complete_lifespan_future,
                lifespan_shutdown_complete,
                _LifespanStopError,
            ),
        )
        lifespan_tg.create_task(lifespan_manager.run())

        # Wait for the application to start. If startup fails, this will raise
        # _LifespanStartError.
        await lifespan_started

        try:
            # Run the rest of the server.
            await _main_coroutine_with_lifespan(
                start_server_fn,
                container,
                listener,
                term_event,
                quit_event,
                shutdown_timeout,
            )
        finally:
            # Shut down the application. If shutdown fails, this will raise
            # _LifespanStopError.
            lifespan_shutting_down.set_result(None)
            await lifespan_shutdown_complete


async def _main_coroutine_with_lifespan(
    start_server_fn: Callable[
        [Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]],
        Awaitable[list[asyncio.Server]],
    ],
    container: Container,
    listener: StartStopListener,
    term_event: asyncio.Event,
    quit_event: asyncio.Event,
    shutdown_timeout: float,
) -> None:
    """
    Run the application in an asyncio event loop within lifespan protocol handling.

    :param start_server_fn: A function which accepts a connection handler and starts and
        returns one or more servers.
    :param container: The ASGI container to use.
    :param listener: The start/stop listener to notify of startup/shutdown.
    :param term_event: An event that is set when the server should shut down.
    :param quit_event: An event that is set when the server should shut down fast.
    :param shutdown_timeout: How long to wait for open connections to finish before
        closing them forcefully.
    """
    log = logging.getLogger(__name__)
    # We use _QuitError only to break through connection_tg. We don’t want it to
    # propagate further out.
    with contextlib.suppress(_QuitError):
        # Create a task group to hold the quit monitor, when created.
        async with asyncio.TaskGroup() as quit_monitor_tg:
            # Create a task group to hold the connection handling tasks, and a timeout
            # that will be scheduled later to bound connection task shutdown time.
            try:
                async with (
                    asyncio.timeout(None) as timeout,
                    asyncio.TaskGroup() as connection_tg,
                ):
                    # Create a connection handler.
                    connection_handler = _ConnectionHandler(container, connection_tg)

                    # Start the server.
                    servers = await start_server_fn(
                        connection_handler.handle_connection,
                    )
                    log.info("Server up and running")

                    # Notify the listener.
                    listener.started()

                    # Wait until requested to terminate.
                    await term_event.wait()
                    log.info("Caught termination signal")

                    # Notify the listener.
                    listener.stopping()

                    # Close the listening sockets.
                    for server in servers:
                        server.close()
                    log.info("Server no longer listening")

                    # While waiting for client connections to finish, we must stop
                    # waiting and cancel them if a fast shutdown is requested. Spawn a
                    # task that will do that.
                    quit_monitor = quit_monitor_tg.create_task(
                        _QuitError.raise_on_event(
                            quit_event,
                        ),
                    )

                    # Start the timeout, giving connection-handling tasks a limit on how
                    # long they have to shut down.
                    timeout.reschedule(
                        asyncio.get_event_loop().time() + shutdown_timeout,
                    )

                    # Wait until all the client connections finish. Each time a task
                    # finishes, it removes itself from the set, and we want to wait
                    # until they are all gone, so just wait for an arbitrary task over
                    # and over until the set is empty.
                    #
                    # In some versions of Python, wait_closed theoretically waits until
                    # the closure of the listening socket is complete, but in practice
                    # doesn’t actually do anything because the listening socket is
                    # closed synchronously. In other versions of Python, wait_closed
                    # does that and also waits until all accepted connections have been
                    # completed as well. Either way, it’s reasonable to call it and to
                    # consider it part of waiting for closure of existing connections.
                    for server in servers:
                        await server.wait_closed()
            except TimeoutError:
                log.warning(
                    (
                        "Some connection tasks did not stop within %.1f second(s) and "
                        "were cancelled"
                    ),
                    shutdown_timeout,
                )
            # Now that all client connections are finished, we don’t need the quit
            # monitor task any more.
            quit_monitor.cancel()
    log.info("All client connections closed")


async def _start_servers_gen(
    tcp_addresses: Iterable[TCPAddress],
    unix_paths: Iterable[pathlib.Path],
    extra_sockets: Iterable[socket.socket],
    handle_connection: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
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
    python_313 = 0x030D00F0
    if sys.hexversion >= python_313:

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
        if extra_socket.family in {socket.AF_INET, socket.AF_INET6}:
            yield await asyncio.start_server(handle_connection, sock=extra_socket)
        elif extra_socket.family == socket.AF_UNIX:
            yield await start_unix_server_from_socket(extra_socket)
        else:
            msg = f"Unrecognized external socket family {extra_socket.family}"
            raise ValueError(msg)
    for tcp_address in tcp_addresses:
        yield await asyncio.start_server(
            handle_connection,
            host=tcp_address.host,
            port=tcp_address.port,
        )
    for unix_path in unix_paths:
        server = await asyncio.start_unix_server(handle_connection, path=unix_path)
        unix_path.chmod(0o666)
        yield server


async def _start_servers(
    tcp_addresses: Iterable[TCPAddress],
    unix_paths: Iterable[pathlib.Path],
    extra_sockets: Iterable[socket.socket],
    handle_connection: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
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
                tcp_addresses,
                unix_paths,
                extra_sockets,
                handle_connection,
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
    shutdown_timeout: float,
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
    :param shutdown_timeout: How long to wait for open connections to finish before
        closing them forcefully.
    """
    asyncio.run(
        _main_coroutine(
            functools.partial(_start_servers, tcp_addresses, unix_paths, extra_sockets),
            container,
            listener,
            shutdown_timeout,
        ),
    )
