"""Tests the core module."""

from __future__ import annotations

import asyncio
import wsgiref.headers
from collections.abc import Coroutine
from contextlib import AbstractAsyncContextManager
from typing import Self, override
from unittest.mock import MagicMock, _Call, call

import pytest
import sioscgi.request
import sioscgi.response

from aioscgi import http
from aioscgi.container import Container
from aioscgi.types import EventOrScope, ReceiveFunction, SendFunction


class EventMatcher:
    """A matcher that compares sioscgi event objects by their contents."""

    __slots__ = {
        "_expected": "The expected value.",
    }

    _expected: sioscgi.response.Event

    def __init__(self: Self, expected: sioscgi.response.Event) -> None:
        """
        Construct a new matcher.

        :param expected: the expected value
        """
        self._expected = expected

    def __eq__(self: Self, actual: object) -> bool:
        """
        Compare a given object to the match target.

        :param actual: the actual value
        """
        if type(self._expected) is not type(actual):
            return False
        if not isinstance(
            self._expected,
            sioscgi.response.Headers | sioscgi.response.Body | sioscgi.response.End,
        ):
            return NotImplemented
        slots = self._expected.__slots__
        if isinstance(slots, str):
            slots = (slots,)
        for k in slots:
            expected_value = getattr(self._expected, k)
            actual_value = getattr(actual, k)
            if type(expected_value) is not type(actual_value):
                return False
            if isinstance(expected_value, wsgiref.headers.Headers):
                if expected_value.items() != actual_value.items():
                    return False
            elif expected_value != actual_value:
                return False
        return True

    def __hash__(self) -> int:
        """Raise an exception as hashing is not needed for this type."""
        raise NotImplementedError

    def __str__(self: Self) -> str:
        """Return the representation of the expected event."""
        return str(self._expected)

    def __repr__(self: Self) -> str:
        """Return the representation of the expected event."""
        return repr(self._expected)


class Connection(http.Connection):
    """
    A mock Connection.

    create_mutex works properly. read_chunk delegates to a mock, provided when the
    object was constructed. write_chunk always fails (expecting not to be called).
    """

    __slots__ = {
        "_read_chunk_call": "The mock to use to implement read_chunk.",
    }

    _read_chunk_call: MagicMock

    def __init__(
        self,
        container: Container,
        read_chunk_call: MagicMock,
    ) -> None:
        """
        Create a new Connection.

        :param container: The ASGI container.
        :param read_chunk_call: The mock to use to implement read_chunk.
        """
        super().__init__(container)
        self._read_chunk_call = read_chunk_call

    @override
    def create_mutex(self: Self) -> AbstractAsyncContextManager[None]:
        return asyncio.Lock()

    @override
    async def read_chunk(self: Self) -> bytes:
        ret = self._read_chunk_call()
        assert isinstance(ret, bytes)
        return ret

    @override
    async def write_chunk(self: Self, _data: bytes, _drain: bool) -> None:
        raise NotImplementedError


def run_test(
    read_events: list[sioscgi.request.Event | None],
    write_events: list[sioscgi.response.Event],
    expected_headers: list[list[bytes]],
    expected_environ: dict[str, bytes],
    expected_messages: list[EventOrScope],
    send_messages: list[EventOrScope],
    *,
    extra_reader_calls: list[_Call] | None = None,
    read_returns_eof: bool = False,
    scheme: str = "http",
) -> None:
    """
    Run a specific application while mocking sioscgi.

    The provided application callable should assert relevant properties about the scope,
    then receive and send messages as required for the test, asserting properties about
    received messages.

    This function does not handle simulations of disconnecting part way through a
    request.

    :param read_events: The sioscgi events that the mock reader will return to aioscgi.
    :param write_events: The sioscgi events that aioscgi should send to the mock writer.
    :param expected_headers: The HTTP headers that the app should see in the scope.
    :param expected_environ: The environment block that the app should see in the scope
        extensions.
    :param expected_messages: The messages that the app should receive from the receive
        callable.
    :param send_messages: The messages that the app will send to the send callable after
        receiving all of :param expected_messages:.
    :param extra_reader_calls: Extra function calls performed on the reader after :param
        read_events:.
    :param read_returns_eof: True if Connection.read_chunk should return EOF (zero
        bytes), or False if Connection.read_chunk should raise NotImplementedError (it
        is not expected to be called at all).
    :param scheme: The scheme that the app should see in the scope.
    """

    async def app(
        scope: EventOrScope,
        receive: ReceiveFunction,
        send: SendFunction,
    ) -> None:
        if scope["type"] == "lifespan":
            msg = "Lifespan protocol not supported by this application"
            raise ValueError(msg)

        assert scope["type"] == "http"
        assert isinstance(scope["asgi"], dict)
        assert scope["asgi"]["version"] == "3.0"
        assert scope["asgi"]["spec_version"] == "2.4"
        assert scope["http_version"] == "1.1"
        assert scope["method"] == "GET"
        assert scope["scheme"] == scheme
        assert scope["path"] == ""
        assert scope["query_string"] == b""
        assert scope["headers"] == expected_headers
        assert scope["server"] == ["localhost", 80]
        extensions = scope["extensions"]
        assert isinstance(extensions, dict)
        environ: dict[str, bytes] = extensions["environ"]
        assert environ == expected_environ

        for expected_message in expected_messages:
            actual_message = await receive()
            assert actual_message == expected_message

        for message in send_messages:
            await send(message)

    with pytest.MonkeyPatch.context() as mp:
        reader_class = MagicMock()
        mp.setattr(sioscgi.request, "SCGIReader", reader_class)
        writer_class = MagicMock()
        mp.setattr(sioscgi.response, "SCGIWriter", writer_class)
        reader = reader_class.return_value
        writer = writer_class.return_value
        reader.next_event.side_effect = read_events
        writer.send.return_value = b""
        container = Container(app, None)
        read_chunk = reader.read_chunk
        if read_returns_eof:
            read_chunk.return_value = b""
        else:
            read_chunk.side_effect = NotImplementedError
        coro = Connection(container, read_chunk).run()
        assert isinstance(coro, Coroutine)
        with pytest.raises(StopIteration):
            coro.send(None)
        assert reader.mock_calls == [
            *(call.next_event() for _ in read_events),
            *(extra_reader_calls or []),
        ]
        assert writer.mock_calls == [call.send(EventMatcher(i)) for i in write_events]


def test_simple() -> None:
    """Test a simple application."""
    run_test(
        [
            sioscgi.request.Headers(
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                },
            ),
            sioscgi.request.End(),
        ],
        [
            sioscgi.response.Headers(
                "200 OK",
                [("Content-Type", "text/plain; charset=UTF-8")],
            ),
            sioscgi.response.Body(b"Hello World!"),
            sioscgi.response.End(),
        ],
        [],
        {
            "SERVER_PROTOCOL": b"HTTP/1.1",
            "REQUEST_METHOD": b"GET",
            "QUERY_STRING": b"",
            "SCRIPT_NAME": b"",
            "SERVER_NAME": b"localhost",
            "SERVER_PORT": b"80",
        },
        [{"type": "http.request"}],
        [
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=UTF-8")],
            },
            {"type": "http.response.body", "body": b"Hello World!"},
        ],
    )


def test_multi_body() -> None:
    """Test request and response bodies transported in multiple parts."""
    run_test(
        [
            sioscgi.request.Headers(
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                    "CONTENT_LENGTH": b"8",
                },
            ),
            sioscgi.request.Body(b"abcd"),
            sioscgi.request.Body(b"efgh"),
            sioscgi.request.End(),
        ],
        [
            sioscgi.response.Headers(
                "200 OK",
                [
                    ("Content-Type", "text/plain; charset=UTF-8"),
                    ("content-length", "12"),
                ],
            ),
            sioscgi.response.Body(b"Hello "),
            sioscgi.response.Body(b"World!"),
            sioscgi.response.End(),
        ],
        [[b"content-length", b"8"]],
        {
            "SERVER_PROTOCOL": b"HTTP/1.1",
            "REQUEST_METHOD": b"GET",
            "QUERY_STRING": b"",
            "SCRIPT_NAME": b"",
            "SERVER_NAME": b"localhost",
            "SERVER_PORT": b"80",
            "CONTENT_LENGTH": b"8",
        },
        [
            {"type": "http.request", "body": b"abcd", "more_body": True},
            {"type": "http.request", "body": b"efgh", "more_body": True},
            {"type": "http.request"},
        ],
        [
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain; charset=UTF-8"),
                    (b"content-length", b"12"),
                ],
            },
            {"type": "http.response.body", "body": b"Hello ", "more_body": True},
            {"type": "http.response.body", "body": b"World!"},
        ],
    )


def test_disconnect_after_request() -> None:
    """Test a long polling client disconnecting before the response body is sent."""
    run_test(
        [
            sioscgi.request.Headers(
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                },
            ),
            sioscgi.request.End(),
        ],
        [],
        [],
        {
            "SERVER_PROTOCOL": b"HTTP/1.1",
            "REQUEST_METHOD": b"GET",
            "QUERY_STRING": b"",
            "SCRIPT_NAME": b"",
            "SERVER_NAME": b"localhost",
            "SERVER_PORT": b"80",
        },
        [
            {"type": "http.request"},
            {"type": "http.disconnect"},
        ],
        [],
        read_returns_eof=True,
        extra_reader_calls=[call.read_chunk()],
    )


def test_disconnect_during_request() -> None:
    """Test a case where the client disconnects while sending the request."""
    run_test(
        [
            sioscgi.request.Headers(
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                    "CONTENT_LENGTH": b"8",
                },
            ),
            sioscgi.request.Body(b"1234"),
            None,
        ],
        [],
        [[b"content-length", b"8"]],
        {
            "SERVER_PROTOCOL": b"HTTP/1.1",
            "REQUEST_METHOD": b"GET",
            "QUERY_STRING": b"",
            "SCRIPT_NAME": b"",
            "SERVER_NAME": b"localhost",
            "SERVER_PORT": b"80",
            "CONTENT_LENGTH": b"8",
        },
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.disconnect"},
        ],
        [],
        read_returns_eof=True,
        extra_reader_calls=[
            call.read_chunk(),
            call.receive_data(b""),
        ],
    )


def test_https() -> None:
    """Test that an HTTPS request is recognized as such."""
    run_test(
        [
            sioscgi.request.Headers(
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                    "HTTPS": b"1",
                },
            ),
            sioscgi.request.End(),
        ],
        [
            sioscgi.response.Headers(
                "200 OK",
                [("Content-Type", "text/plain; charset=UTF-8")],
            ),
            sioscgi.response.Body(b"Hello World!"),
            sioscgi.response.End(),
        ],
        [],
        {
            "SERVER_PROTOCOL": b"HTTP/1.1",
            "REQUEST_METHOD": b"GET",
            "QUERY_STRING": b"",
            "SCRIPT_NAME": b"",
            "SERVER_NAME": b"localhost",
            "SERVER_PORT": b"80",
            "HTTPS": b"1",
        },
        [{"type": "http.request"}],
        [
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=UTF-8")],
            },
            {"type": "http.response.body", "body": b"Hello World!"},
        ],
        scheme="https",
    )
