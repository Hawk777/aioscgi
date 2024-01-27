"""An I/O adapter connecting aioscgi to the Python standard library asyncio."""

import asyncio
import contextlib
import functools
import io
import logging
import os
import signal
from collections.abc import Awaitable, Callable
from typing import Any

from . import core


def _do_nothing() -> None:
    """Do nothing."""


async def _lifespan_coro(
    application: core.ApplicationType,
    lifespan_manager: core.LifespanManager,
    send: Callable[[core.EventOrScope | None], Awaitable[None]],
    receive: Callable[[], Awaitable[core.EventOrScope]],
) -> None:
    """
    Wrap the application coroutine for delivering lifespan protocol events.

    :param application: The application coroutine.
    :param lifespan_manager: The lifespan manager to interact with.
    :param send: A coroutine that, when invoked, sends a value somewhere where the
        LifespanManager’s receive callback can receive it.
    :param receive: A coroutine that, when invoked, waits until the LifespanManager’s
        send callback is invoked and then returns the value thus sent.
    """

    # Wrap the send callable in an extra layer that validates the message before sending
    # it.
    def send_wrapper(event: core.EventOrScope) -> Awaitable[None]:
        core.LifespanManager.check_application_event(event)
        return send(event)

    # Run the application callback. If it returns normally, don’t do anything: while
    # unlikely, it is theoretically possible that the application could have passed its
    # send and receive callables over to another task which is now responsible for
    # handling the lifespan protocol. However, if it returns by raising an exception,
    # then send None, signalling to the LifespanManager that this happened.
    try:
        await application(lifespan_manager.scope, receive, send_wrapper)
    except Exception as exp:  # pylint: disable=broad-except # noqa: BLE001
        logging.getLogger(__name__).debug(
            "Application coroutine raised exception %s for lifespan protocol", exp
        )
        await send(None)


async def _connection_wrapper(
    application: core.ApplicationType,
    client_connections: set[asyncio.Task[None]],
    container: core.Container,
    state: dict[Any, Any],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """
    Run an ASGI application in an asyncio server.

    This function is suitable for passing to ``start_server`` or ``start_unix_server``,
    with the ``application`` and ``client_connections`` parameters bound via a
    ``functools.partial`` or similar.

    :param application: The ASGI application.
    :param client_connections: A set of Task objects, to which this connection is added
        on entry to and removed on exit from this function.
    :param container: The ASGI container to use.
    :param state: The state dictionary that the application can use.
    :param reader: The stream reader for the connection.
    :param writer: The stream writer for the connection.
    """
    # Add this task to the set of open client connections.
    task = asyncio.current_task()
    assert task is not None, "_connection_wrapper must be called inside a task"
    client_connections.add(task)
    try:
        try:
            # aioscgi.run expects callables to read a chunk and write a chunk, the
            # latter taking a drain boolean; adapt the writing side to the stream model
            # (the reader is handled with a functools.partial).
            async def write_cb(data: bytes, drain: bool) -> None:
                writer.write(data)
                if drain:
                    await writer.drain()

            # Run the application.
            await container.run(
                application,
                functools.partial(reader.read, io.DEFAULT_BUFFER_SIZE),
                write_cb,
                state,
            )
        except Exception:  # pylint: disable=broad-except # noqa: BLE001
            logging.getLogger(__name__).error(
                "Uncaught exception in application callable", exc_info=True
            )
        finally:
            # Close the connection.
            try:
                if writer.can_write_eof():
                    writer.write_eof()
                writer.close()
            except Exception:  # pylint: disable=broad-except # noqa: BLE001
                # If something went wrong while closing the connection, there’s nothing
                # interesting to report.
                pass
    finally:
        # Remove this task from the set of open client connections.
        client_connections.remove(task)


async def _main_coroutine(
    application: core.ApplicationType,
    start_server_fn: Callable[..., Awaitable[asyncio.Server]],
    after_listen_cb: Callable[[], None],
    container: core.Container,
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

    # Create the state dictionary.
    state: dict[Any, Any] = {}

    # Start up the lifespan protocol.
    lifespan_app_to_framework_queue: asyncio.Queue[
        core.EventOrScope | None
    ] = asyncio.Queue()
    lifespan_framework_to_app_queue: asyncio.Queue[core.EventOrScope] = asyncio.Queue()
    lifespan_manager = core.LifespanManager(
        lifespan_framework_to_app_queue.put, lifespan_app_to_framework_queue.get, state
    )
    lifespan_future = asyncio.ensure_future(
        _lifespan_coro(
            application,
            lifespan_manager,
            lifespan_app_to_framework_queue.put,
            lifespan_framework_to_app_queue.get,
        )
    )

    try:
        # Start up the application.
        await lifespan_manager.startup()

        try:
            # Start the server and, if provided, run the after listen callback.
            client_connections: set[asyncio.Task[None]] = set()
            srv = await start_server_fn(
                functools.partial(
                    _connection_wrapper,
                    application,
                    client_connections,
                    container,
                    state,
                )
            )
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
            while client_connections:
                await next(iter(client_connections))
            logging.getLogger(__name__).info("All client connections closed")
        finally:
            # Shut down the application.
            await lifespan_manager.shutdown()
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
    application: core.ApplicationType,
    hosts: list[str] | None,
    port: int,
    container: core.Container,
) -> None:
    """
    Run an application listening for SCGI connections on a TCP port.

    :param application: The application callable.
    :param hosts: The list of list of hosts to bind to, or None to bind to all
        interfaces.
    :param port: The port number.
    :param container: The ASGI container to use.
    """
    asyncio.run(
        _main_coroutine(
            application,
            functools.partial(asyncio.start_server, host=hosts, port=port),
            _do_nothing,
            container,
        )
    )


def run_unix(
    application: core.ApplicationType, path: str, container: core.Container
) -> None:
    """
    Run an application listening for SCGI connections on a UNIX socket.

    The socket always has file mode 666. It is not really possible to create a
    UNIX-domain socket with more restrictive permissions from the outset (other than
    perhaps by using umask, which is not thread-safe), and creating it with a more
    permissive mode and then chmodding it afterward leaves an undesirable race
    condition.

    :param application: The application callable.
    :param path: The filename of the socket to listen on.
    :param container: The ASGI container to use.
    """
    asyncio.run(
        _main_coroutine(
            application,
            functools.partial(asyncio.start_unix_server, path=path),
            functools.partial(os.chmod, path, 0o666),
            container,
        )
    )
