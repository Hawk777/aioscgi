"""Data types used by multiple modules."""

import abc
from collections.abc import Awaitable, Callable
from typing import Any, Self

EventOrScopeValue = bytes | str | int | float | list[Any] | dict[str, Any] | bool | None
"""The legal types of values in event or scope dictionaries."""

EventOrScope = dict[str, EventOrScopeValue]
"""The type of an event or scope dictionary."""

ReceiveFunction = Callable[[], Awaitable[EventOrScope]]
"""The type of the receive function."""

SendFunction = Callable[[EventOrScope], Awaitable[None]]
"""The type of the send function."""

ApplicationType = Callable[
    [EventOrScope, ReceiveFunction, SendFunction], Awaitable[Any]
]
"""The type of an ASGI application callable."""


class StartStopListener(abc.ABC):
    """An object that is informed on startup and shutdown."""

    __slots__ = ()

    @abc.abstractmethod
    def started(self: Self) -> None:
        """
        Notify that the server has started.

        At this point the application’s lifespan has started successfully and all
        listening sockets have been created.
        """

    @abc.abstractmethod
    def stopping(self: Self) -> None:
        """
        Notify that the server is beginning to shut down.

        At this point nothing has been done towards shutting down, i.e. the sockets are
        still listening and the application’s lifespan has not begun to end.
        """
