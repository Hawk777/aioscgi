"""Tests the core module."""

from __future__ import annotations

import asyncio
import wsgiref.headers
from collections.abc import Coroutine
from contextlib import AbstractAsyncContextManager
from typing import Self
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

import sioscgi.request
import sioscgi.response

from aioscgi import http
from aioscgi.container import Container
from aioscgi.types import EventOrScope, ReceiveFunction, SendFunction


class EventMatcher:
    """A matcher that compares sioscgi event objects by their contents."""

    __slots__ = {
        "_expected": """The expected value.""",
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

    def __str__(self: Self) -> str:
        """Return the representation of the expected event."""
        return str(self._expected)

    def __repr__(self: Self) -> str:
        """Return the representation of the expected event."""
        return repr(self._expected)


async def _unusable_read_cb() -> bytes:
    """
    Fail when called.

    This function can be used as a read callback in tests where the read callback should
    not be invoked (for example, because the SCGIConnection is mocked to return events
    immediately without asking for any data).
    """
    msg = "This callback should not be called"
    raise NotImplementedError(msg)


async def _unusable_write_cb(_data: bytes, _wait_hint: bool) -> None:
    """
    Fail when called.

    This function can be used as a write callback in tests where the write callback
    should not be invoked (for example, because the SCGIConnection is mocked to store
    the pushed events rather than encoding them into bytes and sending them).
    """
    msg = "This callback should not be called"
    raise NotImplementedError(msg)


class Connection(http.Connection):
    """A mock Connection in which read_chunk and write_chunk cannot be used."""

    def create_mutex(self: Self) -> AbstractAsyncContextManager[None]:  # noqa: D102
        return asyncio.Lock()

    async def read_chunk(self: Self) -> bytes:  # noqa: D102
        raise NotImplementedError

    async def write_chunk(self: Self, _data: bytes, _drain: bool) -> None:  # noqa: D102
        raise NotImplementedError


class TestHTTP(TestCase):
    """Tests the core logic."""

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_simple(
        self: Self, reader_class: MagicMock, writer_class: MagicMock
    ) -> None:
        """Test a simple application."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                msg = "Lifespan protocol not supported by this application"
                raise ValueError(msg)

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.4")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], b"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])
            assert isinstance(scope["extensions"], dict)
            self.assertEqual(
                scope["extensions"]["environ"],
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                },
            )

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain; charset=UTF-8")],
                }
            )
            await send({"type": "http.response.body", "body": b"Hello World!"})

        reader = reader_class.return_value
        writer = writer_class.return_value
        headers = sioscgi.request.Headers(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
            }
        )
        reader.next_event.side_effect = [headers, sioscgi.request.End()]
        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            container = Container(app, None)
            coro = Connection(container).run()
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(reader.mock_calls), [call.next_event(), call.next_event()]
        )
        self.assertEqual(
            list(writer.mock_calls),
            [
                call.send(
                    EventMatcher(
                        sioscgi.response.Headers(
                            "200 OK", [("Content-Type", "text/plain; charset=UTF-8")]
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.response.Body(b"Hello World!"))),
                call.send(EventMatcher(sioscgi.response.End())),
            ],
        )

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_multi_body(
        self: Self, reader_class: MagicMock, writer_class: MagicMock
    ) -> None:
        """Test request and response bodies transported in multiple parts."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                msg = "Lifespan protocol not supported by this application"
                raise ValueError(msg)

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.4")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], b"")
            self.assertEqual(scope["headers"], [[b"content-length", b"8"]])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), b"abcd")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), b"efgh")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/plain; charset=UTF-8"),
                        (b"content-length", b"12"),
                    ],
                }
            )
            await send(
                {"type": "http.response.body", "body": b"Hello ", "more_body": True}
            )
            await send({"type": "http.response.body", "body": b"World!"})

        reader = reader_class.return_value
        writer = writer_class.return_value
        headers = sioscgi.request.Headers(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
                "CONTENT_LENGTH": b"8",
            }
        )
        reader.next_event.side_effect = [
            headers,
            sioscgi.request.Body(b"abcd"),
            sioscgi.request.Body(b"efgh"),
            sioscgi.request.End(),
        ]
        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            container = Container(app, None)
            coro = Connection(container).run()
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(reader.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.next_event(),
                call.next_event(),
            ],
        )
        self.assertEqual(
            list(writer.mock_calls),
            [
                call.send(
                    EventMatcher(
                        sioscgi.response.Headers(
                            "200 OK",
                            [
                                ("Content-Type", "text/plain; charset=UTF-8"),
                                ("content-length", "12"),
                            ],
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.response.Body(b"Hello "))),
                call.send(EventMatcher(sioscgi.response.Body(b"World!"))),
                call.send(EventMatcher(sioscgi.response.End())),
            ],
        )

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_disconnect_after_request(
        self: Self, reader_class: MagicMock, writer_class: MagicMock
    ) -> None:
        """Test a long polling client disconnecting before the response body is sent."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, _: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                msg = "Lifespan protocol not supported by this application"
                raise ValueError(msg)

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.4")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], b"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.disconnect")

        reader = reader_class.return_value
        writer = writer_class.return_value
        headers = sioscgi.request.Headers(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
            }
        )
        reader.next_event.side_effect = [headers, sioscgi.request.End(), None]
        raw_read = reader.raw_read
        raw_read.return_value = b""

        class Conn(Connection):
            """A mock connection that allows reading bytes from the mock source."""

            async def read_chunk(self: Self) -> bytes:
                ret = raw_read()
                assert isinstance(ret, bytes)
                return ret

        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            container = Container(app, None)
            coro = Conn(container).run()
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(reader.mock_calls),
            [call.next_event(), call.next_event(), call.raw_read()],
        )
        self.assertEqual(list(writer.mock_calls), [])

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_disconnect_during_request(
        self: Self, reader_class: MagicMock, writer_class: MagicMock
    ) -> None:
        """Test a case where the client disconnects while sending the request."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, _: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                msg = "Lifespan protocol not supported by this application"
                raise ValueError(msg)

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.4")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], b"")
            self.assertEqual(scope["headers"], [[b"content-length", b"8"]])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), b"1234")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.disconnect")

        reader = reader_class.return_value
        writer = writer_class.return_value
        headers = sioscgi.request.Headers(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
                "CONTENT_LENGTH": b"8",
            }
        )
        reader.next_event.side_effect = [headers, sioscgi.request.Body(b"1234"), None]
        raw_read = reader.raw_read
        raw_read.return_value = b""

        class Conn(Connection):
            """A mock connection that allows reading bytes from the mock source."""

            async def read_chunk(self: Self) -> bytes:
                ret = raw_read()
                assert isinstance(ret, bytes)
                return ret

        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            container = Container(app, None)
            coro = Conn(container).run()
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(reader.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.next_event(),
                call.raw_read(),
                call.receive_data(b""),
            ],
        )
        self.assertEqual(list(writer.mock_calls), [])

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_https(
        self: Self, reader_class: MagicMock, writer_class: MagicMock
    ) -> None:
        """Test that an HTTPS request is recognized as such."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                msg = "Lifespan protocol not supported by this application"
                raise ValueError(msg)

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.4")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "https")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], b"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])
            assert isinstance(scope["extensions"], dict)
            self.assertEqual(
                scope["extensions"]["environ"],
                {
                    "SERVER_PROTOCOL": b"HTTP/1.1",
                    "REQUEST_METHOD": b"GET",
                    "QUERY_STRING": b"",
                    "SCRIPT_NAME": b"",
                    "SERVER_NAME": b"localhost",
                    "SERVER_PORT": b"80",
                    "HTTPS": b"1",
                },
            )

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain; charset=UTF-8")],
                }
            )
            await send({"type": "http.response.body", "body": b"Hello World!"})

        reader = reader_class.return_value
        writer = writer_class.return_value
        headers = sioscgi.request.Headers(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
                "HTTPS": b"1",
            }
        )
        reader.next_event.side_effect = [headers, sioscgi.request.End()]
        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            container = Container(app, None)
            coro = Connection(container).run()
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(reader.mock_calls), [call.next_event(), call.next_event()]
        )
        self.assertEqual(
            list(writer.mock_calls),
            [
                call.send(
                    EventMatcher(
                        sioscgi.response.Headers(
                            "200 OK", [("Content-Type", "text/plain; charset=UTF-8")]
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.response.Body(b"Hello World!"))),
                call.send(EventMatcher(sioscgi.response.End())),
            ],
        )
