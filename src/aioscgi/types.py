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

    Because an instance of this class is the only thing provided by the I/O adapter to
    the protocol handler, it also contains a few I/O-adapter-specific utility methods
    that are not strictly part of socket handling.
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
    def create_one_shot(
        self,
    ) -> tuple[Callable[[], None], Callable[[], Awaitable[Any]]]:
        """
        Create a one-shot notification object.

        :return: A notify function, and a wait function that, when called, waits until
            the notify function is called.
        """

    @abc.abstractmethod
    async def read_chunk(self) -> bytes:
        """
        Read a chunk of bytes from the underlying connection.

        :return: The bytes, or a zero-length bytes object if the underlying connection
            has reached EOF.
        """

    @abc.abstractmethod
    def write_chunk(self, data: bytes) -> None:
        """
        Write a chunk of bytes to the underlying connection.

        This is synchronous, so it must return immediately. It should buffer the data if
        it cannot be passed to the OS immediately; drain_write will be called soon to
        ensure the data does not pile up excessively, but may be called only once for a
        collection of write_chunk calls.

        This method should not raise exceptions due to socket issues.

        :param data: The bytes to write.
        """

    @abc.abstractmethod
    async def drain_write(self) -> None:
        """
        Wait until enough previously written data has been passed to the OS.

        If this is not called, an unlimited amount of data may pile up in userspace
        buffers due to write_chunk calls.

        This may be called by multiple tasks simultaneously.

        If the socket experiences a problem, it should be raised as an exception from
        this method.
        """
