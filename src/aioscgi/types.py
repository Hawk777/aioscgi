"""Data types used by multiple modules."""

from collections.abc import Awaitable, Callable
from typing import Any

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
