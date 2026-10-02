"""The lifespan protocol."""

from __future__ import annotations

import enum
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Never

from .container import Container
from .types import EventOrScope


@enum.unique
class _State(enum.Enum):
    """The states the lifespan protocol can be in."""

    PRE_START = enum.auto()
    """The application has not received the startup event yet."""

    STARTING = enum.auto()
    """The application has received but not responded to the startup event."""

    RUNNING = enum.auto()
    """Startup is complete and shutdown has not started yet."""

    STOPPING = enum.auto()
    """The application has received but not responded to the shutdown event."""

    STOPPED = enum.auto()
    """Shutdown is complete."""

    CRASHED = enum.auto()
    """The application crashed in the lifespan protocol task."""


class _Manager:
    """Implements the ASGI lifespan protocol."""

    __slots__ = {  # noqa: RUF023 the attributes are ordered by function, not name
        "_container": "The ASGI container.",
        "_never": "An awaitable that will never complete.",
        "_started": "A callable to invoke once the application has started up.",
        "_shutting_down": """
            A coroutine function that returns when the server begins shutting down.
            """,
        "_shutdown_complete": """
            A callable to invoke once the application has shut down.
            """,
        "_state": "The current state of the lifespan protocol.",
    }

    _container: Container
    _never: Awaitable[Never]
    _started: Callable[[str | None], None]
    _shutting_down: Callable[[], Awaitable[Any]]
    _shutdown_complete: Callable[[str | None], None]
    _state: _State

    def __init__(
        self,
        container: Container,
        never: Awaitable[Never],
        started: Callable[[str | None], None],
        shutting_down: Callable[[], Awaitable[Any]],
        shutdown_complete: Callable[[str | None], None],
    ) -> None:
        """
        Construct a new _Manager.

        :param container: The ASGI container.
        :param never: An awaitable that will never complete.
        :param started: A callable that _Manager invokes once the application has
            started up, passing the failure message if startup failed or None if startup
            succeeded. This callable is invoked on whatever task the application uses to
            send the lifespan.startup.{complete,failed} event.
        :param shutting_down: A coroutine function that returns when the server begins
            shutting down. The I/O library must not permit this to return until after
            started has been called.
        :param shutdown_complete: A callable that _Manager invokes once the application
            has shut down, passing the failure message if shutdown failed or None if
            shutdown succeeded. This callable is invoked on whatever task the
            application uses to send the lifespan.shutdown.{complete,failed} event.
        """
        self._container = container
        self._never = never
        self._started = started
        self._shutting_down = shutting_down
        self._shutdown_complete = shutdown_complete
        self._state = _State.PRE_START

    async def run(self) -> None:
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
        try:
            await self._container.application(scope, self._receive, self._send)
        # pylint: disable-next=broad-exception-caught
        except Exception:
            # The application crashed in the lifespan protocol. Report the crash, stop
            # giving the application any more lifespan events, and continue the state
            # machine ourself to allow the server as a whole to finish starting up and,
            # when needed, shutting down.
            local_state = self._state
            self._state = _State.CRASHED
            logging.getLogger(__name__).info(
                "Uncaught exception in application callable for lifespan protocol, "
                "proceeding anyway",
                exc_info=True,
            )
            # If, prior to the crash, the application had not completed startup,
            # complete it now, successfully.
            if local_state in {_State.PRE_START, _State.STARTING}:
                self._started(None)
                local_state = _State.RUNNING
            # If the application had not already waited for the shutdown signal, wait
            # for it now.
            if local_state is _State.RUNNING:
                await self._shutting_down()
                local_state = _State.STOPPING
            # If the application had not completed shutdown, complete it now,
            # successfully.
            if local_state is _State.STOPPING:
                self._shutdown_complete(None)

    async def _receive(self) -> EventOrScope:
        """Receive the next lifespan event."""
        while True:
            ret = await self._try_receive()
            if ret is not None:
                return ret

    async def _try_receive(self) -> EventOrScope | None:
        """
        Try to receive a lifespan event.

        :return: The event, or None if this method needs to be called again.
        """
        match self._state:
            case _State.PRE_START:
                # Give the application the startup event.
                self._state = _State.STARTING
                return {"type": "lifespan.startup"}
            case _State.STARTING | _State.RUNNING:
                # Wait until shutdown is initiated.
                await self._shutting_down()
                # The I/O library promises not to let _shutting_down return until after
                # _started has been called. The call to _send that calls _started will
                # change _state to something that is not STARTING, so if it is still
                # STARTING now, then the I/O library broke that promise.
                assert self._state is not _State.STARTING
                # Most likely, we should return the shutdown event now. However, there
                # are two cases in which we should not:
                # 1. The application spawned an additional task from the lifespan
                #    handler. Then, two tasks (either two spawned tasks or one spawned
                #    task and the lifespan handler itself) both called _receive at the
                #    same time. The lifespan.shutdown event should only be received by
                #    one of them. That will be whichever one gets scheduled first. That
                #    task will change _state to STOPPING in addition to returning the
                #    lifespan.shutdown event. Then the second task will be scheduled,
                #    which will see _state as *not* being STARTING or RUNNING any more,
                #    and should *not* return lifespan.shutdown because that would be a
                #    second copy of the event.
                # 2. The application spawned an additional task from the lifespan
                #    handler which called _receive, then the lifespan handler crashed.
                #    The crash will have changed _state to CRASHED. According to the
                #    ASGI specification, in this case, “the server must continue but not
                #    send any lifespan events.” Therefore, we must not return
                #    lifespan.shutdown here in that case.
                # In those two cases, we will return None, causing _try_receive to be
                # called again at which point we will re-evaluate the situation.
                if self._state is _State.RUNNING:
                    self._state = _State.STOPPING
                    return {"type": "lifespan.shutdown"}
                return None
            case _State.STOPPING | _State.STOPPED | _State.CRASHED:
                # No more events should be received in any of these states.
                await self._never
                msg = "Never future completed"
                raise RuntimeError(msg)

    async def _send(self, event: EventOrScope) -> None:
        """
        Send a lifespan event.

        :param event: The event object.
        """
        event_type = event["type"]
        if not isinstance(event_type, str):
            msg = f"type key is of type {type(event_type)}, expected str"
            raise TypeError(msg)

        if event_type.endswith(".complete"):
            error_message = None
        else:
            error_message = event.get("message", "")
            if not isinstance(error_message, str):
                msg = f"message key is of type {type(msg)}, expected str"
                raise TypeError(msg)
        assert isinstance(error_message, str | type(None))

        match self._state:
            case _State.PRE_START:
                msg = f"Event {event_type} sent before receiving lifespan.startup"
                raise ValueError(msg)
            case _State.STARTING:
                self._send_starting(event_type, error_message)
            case _State.RUNNING:
                msg = (
                    f"Event {event_type} sent after lifespan.startup.complete but "
                    "before receiving lifespan.shutdown"
                )
                raise ValueError(msg)
            case _State.STOPPING:
                self._send_stopping(event_type, error_message)
            case _State.STOPPED:
                msg = (
                    f"Event {event_type} sent after lifespan.shutdown.complete or "
                    "lifespan.shutdown.failed"
                )
                raise ValueError(msg)
            case _State.CRASHED:
                # Ignore all events in this state.
                pass

    def _send_starting(self, event_type: str, error_message: str | None) -> None:
        """
        Send a lifespan event in _State.STARTING.

        :param event_type: The event type.
        :param error_message: The error message, or None if :param event_type: is a
            complete event.
        """
        match event_type:
            case "lifespan.startup.complete":
                self._state = _State.RUNNING
                self._started(None)
            case "lifespan.startup.failed":
                self._state = _State.STOPPED
                self._started(error_message)
            case _:
                msg = (
                    f"Event {event_type} sent during startup, expected one of "
                    "lifespan.startup.complete or lifespan.startup.failed"
                )
                raise ValueError(msg)

    def _send_stopping(self, event_type: str, error_message: str | None) -> None:
        """
        Send a lifespan event in _State.STOPPING.

        :param event_type: The event type.
        :param error_message: The error message, or None if :param event_type: is a
            complete event.
        """
        match event_type:
            case "lifespan.shutdown.complete" | "lifespan.shutdown.failed":
                self._state = _State.STOPPED
                self._shutdown_complete(error_message)
            case _:
                msg = (
                    f"Event {event_type} sent during shutdown, expected one of "
                    "lifespan.shutdown.complete or lifespan.shutdown.failed"
                )
                raise ValueError(msg)


async def run(
    container: Container,
    never: Awaitable[Never],
    started: Callable[[str | None], None],
    shutting_down: Callable[[], Awaitable[Any]],
    shutdown_complete: Callable[[str | None], None],
) -> None:
    """
    Run the lifespan protocol.

    This function is meant to be called by an I/O adapter. The intended workflow is as
    follows:
    1.  The adapter constructs the dependencies needed by this function. It passes the
        application callable directly. The other awaitables and the mutex should be
        constructed as appropriate for the I/O library. The callables should typically
        signal awaitables that the adapter’s main task can await, again as appropriate
        for the I/O library.
    2.  The adapter spawns a task which runs this function, passing the dependencies.
    3.  The adapter waits until the started callable is invoked (typically by the
        started callable signalling something which the adapter’s main task is
        awaiting). If an error message was provided, that message should be reported and
        startup aborted.
    4.  The adapter starts listening and running connections.
    5.  The adapter determines it is time to shut down the server.
    6.  The adapter stops listening.
    7.  If appropriate, the adapter waits for ongoing connections to complete. Otherwise
        it may choose to cancel them.
    8.  The adapter causes any current and/or future awaits of shutting_down to return.
    9.  The adapter waits until the shutdown_complete callable is invoked. If an error
        message was provided, that message should be reported.
    10. The adapter waits until the task which called  this function completes.

    The callables will be invoked directly in the task that called this function.

    :param container: The ASGI container.
    :param never: An awaitable that will never complete.
    :param started: A callable that is invoked once the application has started up,
        passing the failure message if startup failed or None if startup succeeded. This
        callable is invoked on whatever task the application uses to send the
        lifespan.startup.{complete,failed} event.
    :param shutting_down: A coroutine function that returns when the server begins
        shutting down. The I/O library must not permit this to return until after
        started has been called.
    :param shutdown_complete: A callable that is invoked once the application has shut
        down, passing the failure message if shutdown failed or None if shutdown
        succeeded. This callable is invoked on whatever task the application uses to
        send the lifespan.shutdown.{complete,failed} event.
    """
    await _Manager(
        container,
        never,
        started,
        shutting_down,
        shutdown_complete,
    ).run()
