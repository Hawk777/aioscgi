"""
Tests the core module.
"""

from unittest import TestCase
from unittest.mock import call, MagicMock, patch
import wsgiref.headers

import sioscgi

import aioscgi.core


def events_equal(event1, event2):
    """
    Check whether two sioscgi events are deeply equal.

    :param event1: the first value
    :param event2: the second value
    :returns: True if event1 and event2 are deeply equal, examining their contents
    """
    if type(event1) is not type(event2):
        return False
    elif isinstance(event1, (sioscgi.RequestHeaders, sioscgi.RequestBody, sioscgi.RequestEnd, sioscgi.ResponseHeaders, sioscgi.ResponseBody, sioscgi.ResponseEnd)):
        slots = event1.__slots__
        if isinstance(slots, str):
            slots = (slots,)
        for k in slots:
            event1_value = getattr(event1, k)
            event2_value = getattr(event2, k)
            if type(event1_value) is not type(event2_value):
                return False
            elif isinstance(event1_value, wsgiref.headers.Headers):
                if event1_value.items() != event2_value.items():
                    return False
            elif event1_value != event2_value:
                return False
        return True
    else:
        raise ValueError("Only applicable to sioscgi events.")


class EventMatcher:
    """
    A matcher that compares sioscgi event objects by their contents.
    """
    __slots__ = ("_expected",)

    def __init__(self, expected):
        """
        Construct a new matcher.

        :param expected: the expected value
        """
        self._expected = expected

    def __eq__(self, actual):
        """
        Compare a given object to the match target.

        :param actual: the actual value
        """
        return events_equal(self._expected, actual)

    def __str__(self):
        return str(self._expected)

    def __repr__(self):
        return repr(self._expected)


class TestCore(TestCase):
    """
    Tests the core logic.
    """

    @patch("sioscgi.SCGIConnection")
    def test_simple(self, conn_class):
        """
        Test a simple application.
        """
        async def app(scope, receive, send):
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], B"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])
            self.assertEqual(scope["extensions"]["environ"], {
                "SERVER_PROTOCOL": B"HTTP/1.1",
                "REQUEST_METHOD": B"GET",
                "QUERY_STRING": B"",
                "SCRIPT_NAME": B"",
                "SERVER_NAME": B"localhost",
                "SERVER_PORT": B"80",
            })

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=UTF-8")]})
            await send({
                "type": "http.response.body",
                "body": B"Hello World!"})
        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders({
            "SERVER_PROTOCOL": B"HTTP/1.1",
            "REQUEST_METHOD": B"GET",
            "QUERY_STRING": B"",
            "SCRIPT_NAME": B"",
            "SERVER_NAME": B"localhost",
            "SERVER_PORT": B"80"})
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd()]
        conn.send.return_value = B""
        with self.assertRaises(StopIteration):
            aioscgi.core.Container(None).run(app, None, None).send(None)
        self.assertEqual(list(conn.mock_calls), [
            call.next_event(),
            call.next_event(),
            call.send(EventMatcher(sioscgi.ResponseHeaders("200 OK", [("Content-Type", "text/plain; charset=UTF-8")]))),
            call.send(EventMatcher(sioscgi.ResponseBody(B"Hello World!"))),
            call.send(EventMatcher(sioscgi.ResponseEnd()))])

    @patch("sioscgi.SCGIConnection")
    def test_multi_body(self, conn_class):
        """
        Test request and response bodies transported in multiple parts.
        """
        async def app(scope, receive, send):
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], B"")
            self.assertEqual(scope["headers"], [[B"content-length", B"8"]])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), B"abcd")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), B"efgh")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=UTF-8"), (b"content-length", b"12")]})
            await send({
                "type": "http.response.body",
                "body": B"Hello ",
                "more_body": True})
            await send({
                "type": "http.response.body",
                "body": B"World!"})
        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders({
            "SERVER_PROTOCOL": B"HTTP/1.1",
            "REQUEST_METHOD": B"GET",
            "QUERY_STRING": B"",
            "SCRIPT_NAME": B"",
            "SERVER_NAME": B"localhost",
            "SERVER_PORT": B"80",
            "CONTENT_LENGTH": B"8"})
        conn.next_event.side_effect = [headers, sioscgi.RequestBody(B"abcd"), sioscgi.RequestBody(B"efgh"), sioscgi.RequestEnd()]
        conn.send.return_value = B""
        with self.assertRaises(StopIteration):
            aioscgi.core.Container(None).run(app, None, None).send(None)
        self.assertEqual(list(conn.mock_calls), [
            call.next_event(),
            call.next_event(),
            call.next_event(),
            call.next_event(),
            call.send(EventMatcher(sioscgi.ResponseHeaders("200 OK", [("Content-Type", "text/plain; charset=UTF-8"), ("content-length", "12")]))),
            call.send(EventMatcher(sioscgi.ResponseBody(B"Hello "))),
            call.send(EventMatcher(sioscgi.ResponseBody(B"World!"))),
            call.send(EventMatcher(sioscgi.ResponseEnd()))])

    @patch("sioscgi.SCGIConnection")
    def test_disconnect_after_request(self, conn_class):
        """
        Test a long polling type of application where the client disconnects
        before the response body is sent.
        """
        async def app(scope, receive, _):
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], B"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.disconnect")

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders({
            "SERVER_PROTOCOL": B"HTTP/1.1",
            "REQUEST_METHOD": B"GET",
            "QUERY_STRING": B"",
            "SCRIPT_NAME": B"",
            "SERVER_NAME": B"localhost",
            "SERVER_PORT": B"80"})
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd(), None]
        raw_read = conn.raw_read
        raw_read.return_value = B""

        async def raw_read_wrapper():
            return raw_read()

        conn.send.return_value = B""
        with self.assertRaises(StopIteration):
            aioscgi.core.Container(None).run(app, raw_read_wrapper, None).send(None)
        self.assertEqual(list(conn.mock_calls), [
            call.next_event(),
            call.next_event(),
            call.raw_read()])

    @patch("sioscgi.SCGIConnection")
    def test_disconnect_during_request(self, conn_class):
        """
        Test a case where the client disconnects while sending the request.
        """
        async def app(scope, receive, _):
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "http")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], B"")
            self.assertEqual(scope["headers"], [[B"content-length", B"8"]])
            self.assertEqual(scope["server"], ["localhost", 80])

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertEqual(message.get("body"), B"1234")
            self.assertTrue(message.get("more_body"))

            message = await receive()
            self.assertEqual(message["type"], "http.disconnect")

        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders({
            "SERVER_PROTOCOL": B"HTTP/1.1",
            "REQUEST_METHOD": B"GET",
            "QUERY_STRING": B"",
            "SCRIPT_NAME": B"",
            "SERVER_NAME": B"localhost",
            "SERVER_PORT": B"80",
            "CONTENT_LENGTH": B"8"})
        conn.next_event.side_effect = [headers, sioscgi.RequestBody(B"1234"), None]
        raw_read = conn.raw_read
        raw_read.return_value = B""

        async def raw_read_wrapper():
            return raw_read()

        conn.send.return_value = B""
        with self.assertRaises(StopIteration):
            aioscgi.core.Container(None).run(app, raw_read_wrapper, None).send(None)
        self.assertEqual(list(conn.mock_calls), [
            call.next_event(),
            call.next_event(),
            call.next_event(),
            call.raw_read(),
            call.receive_data(B"")])

    @patch("sioscgi.SCGIConnection")
    def test_https(self, conn_class):
        """
        Test that an HTTPS request is recognized as such.
        """
        async def app(scope, receive, send):
            if scope["type"] == "lifespan":
                raise ValueError("Lifespan protocol not supported by this application")

            self.assertEqual(scope["type"], "http")
            self.assertEqual(scope["asgi"]["version"], "3.0")
            self.assertEqual(scope["asgi"]["spec_version"], "2.1")
            self.assertEqual(scope["http_version"], "1.1")
            self.assertEqual(scope["method"], "GET")
            self.assertEqual(scope["scheme"], "https")
            self.assertEqual(scope["path"], "")
            self.assertEqual(scope["query_string"], B"")
            self.assertEqual(scope["headers"], [])
            self.assertEqual(scope["server"], ["localhost", 80])
            self.assertEqual(scope["extensions"]["environ"], {
                "SERVER_PROTOCOL": B"HTTP/1.1",
                "REQUEST_METHOD": B"GET",
                "QUERY_STRING": B"",
                "SCRIPT_NAME": B"",
                "SERVER_NAME": B"localhost",
                "SERVER_PORT": B"80",
                "HTTPS": B"1",
            })

            message = await receive()
            self.assertEqual(message["type"], "http.request")
            self.assertFalse(message.get("body"))
            self.assertFalse(message.get("more_body"))

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=UTF-8")]})
            await send({
                "type": "http.response.body",
                "body": B"Hello World!"})
        conn = conn_class.return_value
        headers = sioscgi.RequestHeaders({
            "SERVER_PROTOCOL": B"HTTP/1.1",
            "REQUEST_METHOD": B"GET",
            "QUERY_STRING": B"",
            "SCRIPT_NAME": B"",
            "SERVER_NAME": B"localhost",
            "SERVER_PORT": B"80",
            "HTTPS": B"1"})
        conn.next_event.side_effect = [headers, sioscgi.RequestEnd()]
        conn.send.return_value = B""
        with self.assertRaises(StopIteration):
            aioscgi.core.Container(None).run(app, None, None).send(None)
        self.assertEqual(list(conn.mock_calls), [
            call.next_event(),
            call.next_event(),
            call.send(EventMatcher(sioscgi.ResponseHeaders("200 OK", [("Content-Type", "text/plain; charset=UTF-8")]))),
            call.send(EventMatcher(sioscgi.ResponseBody(B"Hello World!"))),
            call.send(EventMatcher(sioscgi.ResponseEnd()))])

    def test_lifespan_startup_successful(self):
        """
        Test that the lifespan protocol startup events work right for an
        application that supports the protocol and initializes successfully.
        """
        # Create a mock queue and send and receive async callables that access
        # it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.startup.complete"}]

        async def send(event):
            mock_queue.send(event)

        async def receive():
            return mock_queue.receive()

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should return normally.
        with self.assertRaises(StopIteration):
            uut.startup().send(None)

        # The lifespan manager should send the lifespan.startup event, then
        # wait for the application to send the complete message before
        # returning.
        self.assertEqual(mock_queue.mock_calls, [call.send({"type": "lifespan.startup"}), call.receive()])

    def test_lifespan_startup_failed(self):
        """
        Test that the lifespan protocol startup events work right for an
        application that supports the protocol but fails to initialize.
        """
        # Create a mock queue and send and receive async callables that access
        # it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.startup.failed", "message": "Application failure message"}]

        async def send(event):
            mock_queue.send(event)

        async def receive():
            return mock_queue.receive()

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should raise an exception,
        # passing on the message from the application.
        with self.assertRaises(aioscgi.core.ApplicationInitializationError, msg="Application failure message"):
            uut.startup().send(None)

        # The lifespan manager should send the lifespan.startup event, then
        # wait for the application to send the failure message before raising
        # its own exception.
        self.assertEqual(mock_queue.mock_calls, [call.send({"type": "lifespan.startup"}), call.receive()])

    def test_lifespan_shutdown_successful(self):
        """
        Test that the lifespan protocol shutdown events work right for an
        application that supports the protocol and shuts down successfully.
        """
        # Create a mock queue and send and receive async callables that access
        # it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.shutdown.complete"}]

        async def send(event):
            mock_queue.send(event)

        async def receive():
            return mock_queue.receive()

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan shutdown process. It should return normally.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.shutdown event, then
        # wait for the application to send the complete message before
        # returning.
        self.assertEqual(mock_queue.mock_calls, [call.send({"type": "lifespan.shutdown"}), call.receive()])

    def test_lifespan_shutdown_failed(self):
        """
        Test that the lifespan protocol shutdown events work right for an
        application that supports the protocol but fails to shut down.
        """
        # Create a mock queue and send and receive async callables that access
        # it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [{"type": "lifespan.shutdown.failed", "message": "Application failure message"}]

        async def send(event):
            mock_queue.send(event)

        async def receive():
            return mock_queue.receive()

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan shutdown process. It should return normally, because
        # application failures during shutdown don’t really benefit from being
        # reraised at the call site.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.startup event, then
        # wait for the application to send the failure message before raising
        # its own exception.
        self.assertEqual(mock_queue.mock_calls, [call.send({"type": "lifespan.shutdown"}), call.receive()])

    def test_lifespan_not_supported(self):
        """
        Test that the lifespan protocol works properly when the application
        doesn’t support it.
        """
        # Create a mock queue and send and receive async callables that access
        # it.
        mock_queue = MagicMock()
        mock_queue.receive.side_effect = [None]

        async def send(event):
            mock_queue.send(event)

        async def receive():
            return mock_queue.receive()

        # Create the lifespan manager.
        uut = aioscgi.core.LifespanManager(send, receive)

        # At this point, nothing should have been done with the queue.
        self.assertFalse(mock_queue.mock_calls)

        # Run the lifespan startup process. It should return normally. Lack of
        # support from the application should not be considered an error.
        with self.assertRaises(StopIteration):
            uut.startup().send(None)

        # Run the lifespan shutdown process. It should return normally, without
        # doing anything, because of the earlier indication of no support.
        with self.assertRaises(StopIteration):
            uut.shutdown().send(None)

        # The lifespan manager should send the lifespan.startup event, then
        # receive the indication of no support (representing the application
        # callback raising an exception), then not interact with the queue
        # again afterwards.
        self.assertEqual(mock_queue.mock_calls, [call.send({"type": "lifespan.startup"}), call.receive()])
