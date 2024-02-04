"""Tests the core module."""

from __future__ import annotations

import asyncio
import wsgiref.headers
from collections.abc import Coroutine
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

import sioscgi.request
import sioscgi.response

import aioscgi.core
from aioscgi.types import EventOrScope, ReceiveFunction, SendFunction


def events_equal(event1: sioscgi.response.Event, event2: object) -> bool:
    """
    Check whether two sioscgi response events are deeply equal.

    :param event1: the first value
    :param event2: the second value
    :returns: True if event1 and event2 are deeply equal, examining their contents
    """
    if type(event1) is not type(event2):
        return False
    if not isinstance(
        event1,
        sioscgi.response.Headers | sioscgi.response.Body | sioscgi.response.End,
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

    __slots__ = {
        "_expected": """The expected value.""",
    }

    _expected: sioscgi.response.Event

    def __init__(self: EventMatcher, expected: sioscgi.response.Event) -> None:
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


class TestCore(TestCase):
    """Tests the core logic."""

    @patch("sioscgi.response.SCGIWriter")
    @patch("sioscgi.request.SCGIReader")
    def test_simple(
        self: TestCore, reader_class: MagicMock, writer_class: MagicMock
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
            self.assertEqual(scope["asgi"]["spec_version"], "2.3")
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
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb, {}
            )
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
        self: TestCore, reader_class: MagicMock, writer_class: MagicMock
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
            self.assertEqual(scope["asgi"]["spec_version"], "2.3")
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
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb, {}
            )
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
        self: TestCore, reader_class: MagicMock, writer_class: MagicMock
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
            self.assertEqual(scope["asgi"]["spec_version"], "2.3")
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

        async def raw_read_wrapper() -> bytes:
            ret = raw_read()
            assert isinstance(ret, bytes)
            return ret

        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, raw_read_wrapper, _unusable_write_cb, {}
            )
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
        self: TestCore, reader_class: MagicMock, writer_class: MagicMock
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
            self.assertEqual(scope["asgi"]["spec_version"], "2.3")
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

        async def raw_read_wrapper() -> bytes:
            ret = raw_read()
            assert isinstance(ret, bytes)
            return ret

        writer.send.return_value = b""
        with self.assertRaises(StopIteration):
            coro = aioscgi.core.Container(None).run(
                app, raw_read_wrapper, _unusable_write_cb, {}
            )
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
        self: TestCore, reader_class: MagicMock, writer_class: MagicMock
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
            self.assertEqual(scope["asgi"]["spec_version"], "2.3")
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
            coro = aioscgi.core.Container(None).run(
                app, _unusable_read_cb, _unusable_write_cb, {}
            )
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

    def test_lifespan_startup_successful(self: TestCore) -> None:
        """Test successful application startup using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            startup_seen = False
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal startup_seen, shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                startup_seen = True
                await send({"type": "lifespan.startup.complete"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message is None
                started_called = True

            def shutdown_complete(_error_message: str | None) -> None:
                raise NotImplementedError

            uut = aioscgi.core.LifespanManager(
                app,
                loop.create_future(),
                asyncio.Lock(),
                {},
                started,
                loop.create_future(),
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(startup_seen)
            self.assertFalse(started_called)
            self.assertFalse(shutdown_seen)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished.
            self.assertTrue(startup_seen)
            self.assertTrue(started_called)
            self.assertFalse(shutdown_seen)

            # The lifespan manager should keep running after a successful start, so
            # cancel it.
            uut_future.cancel()
            await uut_future

        asyncio.run(impl())

    def test_lifespan_startup_failed(self: TestCore) -> None:
        """Test failed application startup using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            startup_seen = False
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal startup_seen, shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                startup_seen = True
                await send({"type": "lifespan.startup.failed", "message": "FOO"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message == "FOO"
                started_called = True

            def shutdown_complete(_error_message: str | None) -> None:
                raise NotImplementedError

            uut = aioscgi.core.LifespanManager(
                app,
                loop.create_future(),
                asyncio.Lock(),
                {},
                started,
                loop.create_future(),
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(startup_seen)
            self.assertFalse(started_called)
            self.assertFalse(shutdown_seen)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished.
            self.assertTrue(startup_seen)
            self.assertTrue(started_called)
            self.assertFalse(shutdown_seen)

            # The lifespan manager should return promptly after failed startup.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_shutdown_successful(self: TestCore) -> None:
        """Test successful application shutdown using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                await send({"type": "lifespan.startup.complete"})
                event = await receive()
                assert event["type"] == "lifespan.shutdown"
                shutdown_seen = True
                await send({"type": "lifespan.shutdown.complete"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()

            def started(error_message: str | None) -> None:
                assert error_message is None

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message is None
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = aioscgi.core.LifespanManager(
                app,
                loop.create_future(),
                asyncio.Lock(),
                {},
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(shutdown_seen)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_shutdown_failed(self: TestCore) -> None:
        """Test failed application shutdown using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                await send({"type": "lifespan.startup.complete"})
                event = await receive()
                assert event["type"] == "lifespan.shutdown"
                shutdown_seen = True
                await send({"type": "lifespan.shutdown.failed", "message": "FOO"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()

            def started(error_message: str | None) -> None:
                assert error_message is None

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message == "FOO"
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = aioscgi.core.LifespanManager(
                app,
                loop.create_future(),
                asyncio.Lock(),
                {},
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(shutdown_seen)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_not_supported(self: TestCore) -> None:
        """Test an application not supporting the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            async def app(
                _scope: EventOrScope, _receive: ReceiveFunction, _send: SendFunction
            ) -> None:
                msg = "Lifespan protocol not supported"
                raise ValueError(msg)

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message is None
                started_called = True

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message is None
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = aioscgi.core.LifespanManager(
                app,
                loop.create_future(),
                asyncio.Lock(),
                {},
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(started_called)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertTrue(started_called)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(started_called)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())
