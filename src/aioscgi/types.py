"""Data types used by multiple modules."""

import abc
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
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
    [EventOrScope, ReceiveFunction, SendFunction],
    Awaitable[Any],
]
"""The type of an ASGI application callable."""


class StartStopListener(abc.ABC):
    """An object that is informed on startup and shutdown."""

    __slots__ = ()

    @abc.abstractmethod
    def started(self) -> None:
        """
        Notify that the server has started.

        At this point the application’s lifespan has started successfully and all
        listening sockets have been created.
        """

    @abc.abstractmethod
    def stopping(self) -> None:
        """
        Notify that the server is beginning to shut down.

        At this point nothing has been done towards shutting down, i.e. the sockets are
        still listening and the application’s lifespan has not begun to end.
        """


class Socket(abc.ABC):
    """
    A socket speaking the SCGI protocol over which data can be read and written.

    Each time the I/O adapter accepts a new incoming connection, it must create a new
    instance of an I/O-adapter-specific subclass of this class (in a common task or in a
    dedicated per-connection task), which is then passed to the appropriate protocol
    handling routine.
    """

    __slots__ = ()

    @abc.abstractmethod
    def create_mutex(self) -> AbstractAsyncContextManager[None]:
        """
        Create a mutex.

        :return: An object that can be used as an asynchronous context manager, such
            that only one async task can be within the context at a time.
        """

    @abc.abstractmethod
    async def read_chunk(self) -> bytes:
        """
        Read a chunk of bytes from the underlying connection.

        :return: The bytes, or a zero-length bytes object if the underlying connection
            has reached EOF.
        """

    @abc.abstractmethod
    async def write_chunk(self, data: bytes, drain: bool) -> None:
        """
        Write a chunk of bytes to the underlying connection.

        :param data: The bytes to write.
        :param drain: True if the function should wait until the data has been accepted
            by the kernel before returning.
        """
