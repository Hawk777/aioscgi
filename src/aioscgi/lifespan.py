"""The lifespan protocol."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any, Self

from .container import Container
from .types import ApplicationType, EventOrScope, ReceiveFunction, SendFunction


def _wrapper(application: ApplicationType, never: Awaitable[None]) -> ApplicationType:
    """
    Wrap the application callable for the lifespan protocol and deal with exceptions.

    :param application: The application.
    :param never: An awaitable that will never complete.
    :return: A wrapped callable that will not raise exceptions.
    """

    async def impl(
        scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
    ) -> None:
        nonlocal application, never

        # Track whether each type of message has occurred yet.
        startup_received = False
        startup_complete_sent = False
        shutdown_received = False
        shutdown_complete_sent = False

        # Track whether the application callable has crashed. According to the spec, if
        # the lifespan coroutine crashes, no more lifespan events should be passed to
        # (and presumably received from) the application; however, the lifespan
        # coroutine could have handed copies of the send and receive functions to
        # another task before crashing, so to comply with the spec, we must prevent
        # *that* task from calling receive and seeing an event as well.
        crashed = False

        # Wrap the send and receive functions to be passed into the application so that
        # they track the state.
        async def wrapped_receive() -> EventOrScope:
            nonlocal crashed, startup_received, shutdown_received
            if crashed:
                # The application callable crashed, so per the spec, the application as
                # a whole should not see any more lifespan events.
                await never
            event = await receive()
            match event["type"]:
                case "lifespan.startup":
                    startup_received = True
                case "lifespan.shutdown":
                    shutdown_received = True
            return event

        async def wrapped_send(event: EventOrScope) -> None:
            nonlocal crashed, startup_complete_sent, shutdown_complete_sent
            if crashed:
                # The application callable crashed, so the application should no longer
                # be involved in lifespan tracking.
                return None
            match event.get("type"):
                case "lifespan.startup.complete" | "lifespan.startup.failed":
                    startup_complete_sent = True
                case "lifespan.shutdown.complete" | "lifespan.shutdown.failed":
                    shutdown_complete_sent = True
            return await send(event)

        # Delegate to the application callable, catching exceptions.
        try:
            await application(scope, wrapped_receive, wrapped_send)
        except Exception:  # pylint: disable=broad-except # noqa: BLE001
            # Per the spec, exceptions raised by the application callable for a lifespan
            # scope should not prevent the server from working, but should just indicate
            # no support for the lifespan protocol. Run whatever is left of the lifespan
            # protocol locally, so the Manager can just assume lifespan is always
            # supported.
            crashed = True
            logging.getLogger(__name__).info(
                "Uncaught exception in application callable for lifespan protocol, "
                "proceeding anyway",
                exc_info=True,
            )
            while not startup_received:
                match (await receive())["type"]:
                    case "lifespan.startup":
                        startup_received = True
                    case "lifespan.shutdown":
                        shutdown_received = True
            if not startup_complete_sent:
                await send({"type": "lifespan.startup.complete"})
            while not shutdown_received:
                shutdown_received = (await receive())["type"] == "lifespan.shutdown"
            if not shutdown_complete_sent:
                await send({"type": "lifespan.shutdown.complete"})

    return impl


class Manager:
    """
    Implements the ASGI lifespan protocol.

    This class is meant for use by an I/O adapter. The intended workflow is as follows:
    1.  The adapter constructs a Manager class. It passes the application callable
        directly. The other awaitables and the mutex should be constructed as
        appropriate for the I/O library. The callables should typically signal
        awaitables that the adapter’s main task can await, again as appropriate for the
        I/O library.
    2.  The adapter spawns a task which runs the Manager’s run method.
    3.  The adapter waits until the started callable is invoked (typically by the
        started callable signalling something which the adapter’s main task is
        awaiting). If an error message was provided, that message should be reported and
        startup aborted.
    4.  The adapter starts listening and running connections.
    5.  The adapter determines it is time to shut down the server.
    6.  The adapter stops listening.
    7.  If appropriate, the adapter waits for ongoing connections to complete. Otherwise
        it may choose to cancel them.
    8.  The adapter causes the awaitable passed as shutting_down to become ready.
    9.  The adapter waits until the shutdown_complete callable is invoked. If an error
        message was provided, that message should be reported.
    10. The adapter waits until the task which called the run method completes.
    """

    __slots__ = {  # noqa: RUF023 the attributes are ordered by function, not name
        "_container": """The ASGI container.""",
        "_wrapped_application": """The application, wrapped for exception handling.""",
        "_never": """An awaitable that will never complete.""",
        "_started": """A callable to invoke once the application has started up.""",
        "_started_called": """Whether _started has been called.""",
        "_shutting_down": """
            An awaitable that becomes ready when the server begins shutting down.
            """,
        "_shutdown_complete": """
            A callable to invoke once the application has shut down.
            """,
        "_shutdown_complete_called": """Whether _shutdown_complete has been called.""",
        "_startup_done": """Whether startup.{complete,failed} was sent.""",
        "_shutdown_done": """Whether shutdown.{complete,failed} was sent.""",
        "_receive_mutex": """A mutex used to protect concurrent receives.""",
        "_receive_iter": """An asynchronous iterator over the events to receive.""",
    }

    _container: Container
    _wrapped_application: ApplicationType
    _never: Awaitable[None]
    _started: Callable[[str | None], None]
    _started_called: bool
    _shutting_down: Awaitable[None]
    _shutdown_complete: Callable[[str | None], None]
    _shutdown_complete_called: bool
    _receive_mutex: AbstractAsyncContextManager[Any]
    _receive_iter: AsyncIterator[EventOrScope]

    def __init__(
        self: Self,
        container: Container,
        never: Awaitable[None],
        mutex: AbstractAsyncContextManager[Any],
        started: Callable[[str | None], None],
        shutting_down: Awaitable[None],
        shutdown_complete: Callable[[str | None], None],
    ) -> None:
        """
        Construct a new Manager.

        The callables will be invoked in the task that runs the lifespan protocol.

        :param container: The ASGI container.
        :param never: An awaitable that will never complete.
        :param mutex: A mutex (async context manager that can only be entered by one
            task at a time) that the lifespan manager can use internally and that is not
            used by the caller in any way.
        :param started: A callable that Manager invokes once the application has started
            up, passing the failure message if startup failed or None if startup
            succeeded.
        :param shutting_down: An awaitable that the caller makes ready when the server
            begins shutting down.
        :param shutdown_complete: A callable that Manager invokes once the application
            has shut down, passing the failure message if shutdown failed or None if
            shutdown succeeded.
        """
        self._container = container
        self._wrapped_application = _wrapper(container.application, never)
        self._never = never
        self._started = started
        self._started_called = False
        self._shutting_down = shutting_down
        self._shutdown_complete = shutdown_complete
        self._shutdown_complete_called = False
        self._receive_mutex = mutex
        self._receive_iter = self._receive_gen()

    async def run(self: Self) -> Any:
        """
        Run the lifespan protocol.

        This method should be invoked in a separate task.
        """
        scope: EventOrScope = {
            "type": "lifespan",
            "asgi": {
                "version": "3.0",
                "spec_version": "2.0",
            },
            "state": self._container.state,
        }
        return await self._wrapped_application(scope, self._receive, self._send)

    async def _receive_gen(self: Self) -> AsyncIterator[EventOrScope]:
        """Generate events for the application to receive."""
        yield {"type": "lifespan.startup"}
        await self._shutting_down
        yield {"type": "lifespan.shutdown"}
        await self._never

    async def _receive(self: Self) -> EventOrScope:
        """Receive the next lifespan event."""
        async with self._receive_mutex:
            return await anext(self._receive_iter)

    async def _send(self: Self, event: EventOrScope) -> None:
        event_type = event["type"]
        assert isinstance(event_type, str)
        parts = event_type.split(".")
        if (
            len(parts) != 3
            or parts[0] != "lifespan"
            or parts[1] not in ("startup", "shutdown")
            or parts[2] not in ("complete", "failed")
        ):
            msg = (
                f"Unrecognized event type {event_type}, expected "
                "lifespan.{startup,shutdown}.{complete,failed}"
            )
            raise ValueError(msg)
        stage = parts[1]
        outcome = parts[2]

        if outcome == "complete":
            error_message = None
        else:
            error_message = event.get("message", "")
            if not isinstance(error_message, str):
                msg = f"message key is of type {type(msg)}, expected str"
                raise TypeError(msg)
        assert isinstance(error_message, str | type(None))

        if stage == "startup":
            if self._started_called:
                msg = "lifespan.startup.{complete,failed} sent multiple times"
                raise ValueError(msg)
            self._started_called = True
            self._started(error_message)
        else:
            if self._shutdown_complete_called:
                msg = "lifespan.shutdown.{complete,failed} sent multiple times"
                raise ValueError(msg)
            self._shutdown_complete_called = True
            self._shutdown_complete(error_message)
