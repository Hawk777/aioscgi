"""Tests the core module."""

from __future__ import annotations

import wsgiref.headers
from collections.abc import Coroutine
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

import sioscgi

import aioscgi.core
from aioscgi.core import EventOrScope, ReceiveFunction, SendFunction


def events_equal(event1: sioscgi.Event, event2: object) -> bool:
    """
    Check whether two sioscgi events are deeply equal.

    :param event1: the first value
    :param event2: the second value
    :returns: True if event1 and event2 are deeply equal, examining their contents
    """
    if type(event1) is not type(event2):
        return False
    if not isinstance(
        event1,
        sioscgi.RequestHeaders
        | sioscgi.RequestBody
        | sioscgi.RequestEnd
        | sioscgi.ResponseHeaders
        | sioscgi.ResponseBody
        | sioscgi.ResponseEnd,
    ):
        return NotImplemented
    slots = event1.__slots__
    if isinstance(slots, str):
        slots = (slots,)
    for k in slots:
        event1_value = getattr(event1, k)
        event2_value = getattr(event2, k)
        if type(event1_value) is not type(event2_value):
            return False
        if isinstance(event1_value, wsgiref.headers.Headers):
            if event1_value.items() != event2_value.items():
                return False
        elif event1_value != event2_value:
            return False
    return True


class EventMatcher:
    """A matcher that compares sioscgi event objects by their contents."""

    __slots__ = ("_expected",)

    def __init__(self: EventMatcher, expected: sioscgi.Event) -> None:
        """
        Construct a new matcher.

        :param expected: the expected value
        """
        self._expected = expected

    def __eq__(self: EventMatcher, actual: object) -> bool:
        """
        Compare a given object to the match target.

        :param actual: the actual value
        """
        return events_equal(self._expected, actual)

    def __str__(self: EventMatcher) -> str:
        """Return the representation of the expected event."""
        return str(self._expected)

    def __repr__(self: EventMatcher) -> str:
        """Return the representation of the expected event."""
        return repr(self._expected)


async def _unusable_read_cb() -> bytes:
    """
    Fail when called.

    This function can be used as a read callback in tests where the read
    callback should not be invoked (for example, because the SCGIConnection is
    mocked to return events immediately without asking for any data).
    """
    raise NotImplementedError("This callback should not be called")


async def _unusable_write_cb(_data: bytes, _wait_hint: bool) -> None:
    """
    Fail when called.

    This function can be used as a write callback in tests where the write
    callback should not be invoked (for example, because the SCGIConnection is
    mocked to store the pushed events rather than encoding them into bytes and
    sending them).
    """
    raise NotImplementedError("This callback should not be called")


class TestCore(TestCase):
    """Tests the core logic."""

    @patch("sioscgi.SCGIConnection")
    def test_simple(self: TestCore, conn_class: MagicMock) -> None:
        """Test a simple application."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
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

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
            }
        )
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd()]
        conn.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb
            )
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(conn.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.send(
                    EventMatcher(
                        sioscgi.ResponseHeaders(
                            "200 OK", [("Content-Type", "text/plain; charset=UTF-8")]
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.ResponseBody(b"Hello World!"))),
                call.send(EventMatcher(sioscgi.ResponseEnd())),
            ],
        )

    @patch("sioscgi.SCGIConnection")
    def test_multi_body(self: TestCore, conn_class: MagicMock) -> None:
        """Test request and response bodies transported in multiple parts."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
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

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders(
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
        conn.next_event.side_effect = [
            headers,
            sioscgi.RequestBody(b"abcd"),
            sioscgi.RequestBody(b"efgh"),
            sioscgi.RequestEnd(),
        ]
        conn.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb
            )
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(conn.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.next_event(),
                call.next_event(),
                call.send(
                    EventMatcher(
                        sioscgi.ResponseHeaders(
                            "200 OK",
                            [
                                ("Content-Type", "text/plain; charset=UTF-8"),
                                ("content-length", "12"),
                            ],
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.ResponseBody(b"Hello "))),
                call.send(EventMatcher(sioscgi.ResponseBody(b"World!"))),
                call.send(EventMatcher(sioscgi.ResponseEnd())),
            ],
        )

    @patch("sioscgi.SCGIConnection")
    def test_disconnect_after_request(self: TestCore, conn_class: MagicMock) -> None:
        """
        Test a long polling type of application where the client disconnects
        before the response body is sent.
        """

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, _: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
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

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders(
            {
                "SERVER_PROTOCOL": b"HTTP/1.1",
                "REQUEST_METHOD": b"GET",
                "QUERY_STRING": b"",
                "SCRIPT_NAME": b"",
                "SERVER_NAME": b"localhost",
                "SERVER_PORT": b"80",
            }
        )
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd(), None]
        raw_read = conn.raw_read
        raw_read.return_value = b""

        async def raw_read_wrapper() -> bytes:
            ret = raw_read()
            assert isinstance(ret, bytes)
            return ret

        conn.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, raw_read_wrapper, _unusable_write_cb
            )
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(conn.mock_calls),
            [call.next_event(), call.next_event(), call.raw_read()],
        )

    @patch("sioscgi.SCGIConnection")
    def test_disconnect_during_request(self: TestCore, conn_class: MagicMock) -> None:
        """Test a case where the client disconnects while sending the request."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, _: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
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

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders(
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
        conn.next_event.side_effect = [headers, sioscgi.RequestBody(b"1234"), None]
        raw_read = conn.raw_read
        raw_read.return_value = b""

        async def raw_read_wrapper() -> bytes:
            ret = raw_read()
            assert isinstance(ret, bytes)
            return ret

        conn.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, raw_read_wrapper, _unusable_write_cb
            )
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(conn.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.next_event(),
                call.raw_read(),
                call.receive_data(b""),
            ],
        )

    @patch("sioscgi.SCGIConnection")
    def test_https(self: TestCore, conn_class: MagicMock) -> None:
        """Test that an HTTPS request is recognized as such."""

        async def app(
            scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
        ) -> None:
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            assert isinstance(scope["asgi"], dict)
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
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

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders(
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
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd()]
        conn.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb
            )
            assert isinstance(coro, Coroutine)
            coro.send(None)
        self.assertEqual(
            list(conn.mock_calls),
            [
                call.next_event(),
                call.next_event(),
                call.send(
                    EventMatcher(
                        sioscgi.ResponseHeaders(
                            "200 OK", [("Content-Type", "text/plain; charset=UTF-8")]
                        )
                    )
                ),
                call.send(EventMatcher(sioscgi.ResponseBody(b"Hello World!"))),
                call.send(EventMatcher(sioscgi.ResponseEnd())),
            ],
        )

    def test_lifespan_startup_successful(self: TestCore) -> None:
        """
        Test that the lifespan protocol startup events work right for an
        application that supports the protocol and initializes successfully.
        """
        # Create a mock queue and send and receive async callables that access it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.startup.complete"}]

        async def send(event: EventOrScope) -> None:
            mock_queue.send(event)

        async def receive() -> EventOrScope | None:
            ret = mock_queue.receive()
            assert isinstance(ret, dict)
            return ret

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should return normally.
        with self.assertRaises(StopIteration):
            uut.startup().send(None)

        # The lifespan manager should send the lifespan.startup event, then wait for the
        # application to send the complete message before returning.
        self.assertEqual(
            mock_queue.mock_calls,
            [call.send({"type": "lifespan.startup"}), call.receive()],
        )

    def test_lifespan_startup_failed(self: TestCore) -> None:
        """
        Test that the lifespan protocol startup events work right for an
        application that supports the protocol but fails to initialize.
        """
        # Create a mock queue and send and receive async callables that access it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [
            {
                "type": "lifespan.startup.failed",
                "message": "Application failure message",
            }
        ]

        async def send(event: EventOrScope) -> None:
            mock_queue.send(event)

        async def receive() -> EventOrScope | None:
            ret = mock_queue.receive()
            assert isinstance(ret, dict)
            return ret

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should raise an exception, passing on the
        # message from the application.
        with self.assertRaises(
            aioscgi.core.ApplicationInitializationError,
            msg="Application failure message",
        ):
            uut.startup().send(None)

        # The lifespan manager should send the lifespan.startup event, then wait for the
        # application to send the failure message before raising its own exception.
        self.assertEqual(
            mock_queue.mock_calls,
            [call.send({"type": "lifespan.startup"}), call.receive()],
        )

    def test_lifespan_shutdown_successful(self: TestCore) -> None:
        """
        Test that the lifespan protocol shutdown events work right for an
        application that supports the protocol and shuts down successfully.
        """
        # Create a mock queue and send and receive async callables that access it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.shutdown.complete"}]

        async def send(event: EventOrScope) -> None:
            mock_queue.send(event)

        async def receive() -> EventOrScope | None:
            ret = mock_queue.receive()
            assert isinstance(ret, dict)
            return ret

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan shutdown process. It should return normally.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.shutdown event, then wait for
        # the application to send the complete message before returning.
        self.assertEqual(
            mock_queue.mock_calls,
            [call.send({"type": "lifespan.shutdown"}), call.receive()],
        )

    def test_lifespan_shutdown_failed(self: TestCore) -> None:
        """
        Test that the lifespan protocol shutdown events work right for an
        application that supports the protocol but fails to shut down.
        """
        # Create a mock queue and send and receive async callables that access it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [
            {
                "type": "lifespan.shutdown.failed",
                "message": "Application failure message",
            }
        ]

        async def send(event: EventOrScope) -> None:
            mock_queue.send(event)

        async def receive() -> EventOrScope | None:
            ret = mock_queue.receive()
            assert isinstance(ret, dict)
            return ret

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan shutdown process. It should return normally, because
        # application failures during shutdown don’t really benefit from being reraised
        # at the call site.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.startup event, then wait for the
        # application to send the failure message before raising its own exception.
        self.assertEqual(
            mock_queue.mock_calls,
            [call.send({"type": "lifespan.shutdown"}), call.receive()],
        )

    def test_lifespan_not_supported(self: TestCore) -> None:
        """
        Test that the lifespan protocol works properly when the application
        doesn’t support it.
        """
        # Create a mock queue and send and receive async callables that access it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [None]

        async def send(event: EventOrScope) -> None:
            mock_queue.send(event)

        async def receive() -> EventOrScope | None:
            ret = mock_queue.receive()
            assert ret is None
            return ret

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should return normally. Lack of support
        # from the application should not be considered an error.
        with self.assertRaises(StopIteration):
            uut.startup().send(None)

        # Run the lifespan shutdown process. It should return normally, without doing
        # anything, because of the earlier indication of no support.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.startup event, then receive the
        # indication of no support (representing the application callback raising an
        # exception), then not interact with the queue again afterwards.
        self.assertEqual(
            mock_queue.mock_calls,
            [call.send({"type": "lifespan.startup"}), call.receive()],
        )
