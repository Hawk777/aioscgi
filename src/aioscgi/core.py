"""
The core server.

The server implemented in this module runs an ASGI application.

The main entry point is the run function.
"""

from __future__ import annotations

import http
import logging
import wsgiref.util
from collections.abc import Awaitable, Callable
from typing import Any

import sioscgi.request
import sioscgi.response

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


class ApplicationInitializationError(Exception):
    """
    Raised if the application fails during lifespan startup.

    This covers the case where the application replies to the lifespan startup event
    with a lifespan startup failed event. It is not used if the application raises an
    exception during lifespan startup.
    """

    __slots__ = ()


class LifespanManager:
    """Implements the ASGI lifespan protocol."""

    __slots__ = {
        "_send": """A coroutine that sends an event to the application.""",
        "_receive": """A coroutine that receives an event from the application.""",
        "_unsupported": """True if the application coroutine raised an exception.""",
        "_state": """The application state dictionary.""",
    }

    _send: SendFunction
    _receive: Callable[[], Awaitable[EventOrScope | None]]
    _unsupported: bool
    _state: dict[Any, Any]

    def __init__(
        self: LifespanManager,
        send: SendFunction,
        receive: Callable[[], Awaitable[EventOrScope | None]],
        state: dict[Any, Any],
    ) -> None:
        """
        Construct a new LifespanManager.

        :param send: A coroutine which, when invoked, queues the passed-in event so that
            it can be received by the application coroutine instance running the
            lifespan protocol.
        :param receive: A coroutine which, when invoked, waits until the application
            coroutine instance running the lifespan protocol sends an event, then
            returns that event, or None if the application coroutine terminates with an
            exception.
        :param state: The state dictionary that the application can use.
        """
        self._send = send
        self._receive = receive
        self._unsupported = False
        self._state = state

    @property
    def scope(self: LifespanManager) -> EventOrScope:
        """The scope that should be passed to the application callable."""
        return {
            "type": "lifespan",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
            "state": self._state,
        }

    @staticmethod
    def check_application_event(event: EventOrScope) -> None:
        """
        Sanity check an event passed in by the application coroutine.

        :param event: The event to check.
        """
        event_type = event["type"]
        if event_type not in (
            "lifespan.startup.complete",
            "lifespan.startup.failed",
            "lifespan.shutdown.complete",
            "lifespan.shutdown.failed",
        ):
            msg = f"Unknown event type {event_type!r}"
            raise ValueError(msg)

    async def startup(self: LifespanManager) -> None:
        """
        Perform the application startup process.

        :raises ApplicationInitializationError: if the application fails to initialize
        """
        logging.getLogger(__name__).debug("LifespanManager sending startup message")
        await self._send({"type": "lifespan.startup"})
        reply = await self._receive()
        logging.getLogger(__name__).debug(
            "LifespanManager received startup reply: %s", reply
        )
        if reply is None:
            # The application coroutine terminated with an exception, which the I/O
            # adapter encoded as a None in the receive queue. This means that the
            # application does not support the lifespan protocol, which is totally fine
            # and just means we should not send more lifespan message.
            self._unsupported = True
        else:
            reply_type = reply["type"]
            if reply_type == "lifespan.startup.complete":
                # The application finished initializing successfully.
                pass
            elif reply_type == "lifespan.startup.failed":
                # The application failed to initialize.
                raise ApplicationInitializationError(reply.get("message", ""))
            else:
                msg = f"Unknown message type {reply_type!r}"
                raise ValueError(msg)

    async def shutdown(self: LifespanManager) -> None:
        """
        Perform the application shutdown process.

        Failures are not reported to the caller, because failures during shutdown don’t
        really mean anything.
        """
        if not self._unsupported:
            logging.getLogger(__name__).debug(
                "LifespanManager sending shutdown message"
            )
            await self._send({"type": "lifespan.shutdown"})
            reply = await self._receive()
            logging.getLogger(__name__).debug(
                "LifespanManager received shutdown reply: %s", reply
            )
            if reply is None:
                # The application coroutine terminated with an exception, which the I/O
                # adapter encoded as a None in the receive queue. This means that the
                # application does not support the lifespan protocol, which is totally
                # fine and just means we should not send more lifespan message.
                # Obviously we shouldn’t ever *try* to send another one, since we just
                # finished shutdown, but just in case, remember the situation.
                self._unsupported = True
            else:
                reply_type = reply["type"]
                if reply_type in (
                    "lifespan.shutdown.complete",
                    "lifespan.shutdown.failed",
                ):
                    # The application has finished shutting down, successfully or
                    # otherwise.
                    pass
                else:
                    msg = f"Unknown message type {reply_type!r}"
                    raise ValueError(msg)


def _calc_http_version(server_protocol: bytes) -> str:
    """
    Convert an HTTP_PROTOCOL environment value into an HTTP protocol version string.

    :param server_protocol: The value of the CGI ``SERVER_PROTOCOL`` variable.
    :returns: The HTTP version in use.
    """
    server_protocol_str = server_protocol.decode("UTF-8").upper()
    if server_protocol_str.startswith("HTTP/"):
        return server_protocol_str[len("HTTP/") :]
    if server_protocol == b"INCLUDED":
        return "1.0"
    msg = f"Unrecognized HTTP protocol version {server_protocol_str}"
    raise ValueError(msg)


def _guess_scheme(environ: dict[str, bytes]) -> str:
    """
    Guess the URL scheme (http or https).

    :param environ: The CGI environment dictionary.
    :returns: The guessed scheme.
    """
    # wsgiref.util.guess_scheme will do the work for us, but it requires a dict[str,
    # str], not a dict[str, bytes]. It works by looking for a key named “HTTPS” and
    # examining its value. Rather than doing the work of decoding the entire environment
    # dictionary to a dict[str, str], just decode only the HTTPS key if present.
    https = environ.get("HTTPS")
    if https is None:
        return "http"
    return wsgiref.util.guess_scheme({"HTTPS": https.decode("ISO-8859-1")})


def _calc_http_headers(environ: dict[str, bytes]) -> list[list[bytes]]:
    """
    Extract the HTTP headers from the environment dictionary.

    :param environ: The CGI environment dictionary.
    :returns: The HTTP headers as a list of two-element lists of bytes, suitable for
        passing to an ASGI application.
    """
    return [
        [k.replace("HTTP_", "", 1).replace("_", "-").lower().encode("ISO-8859-1"), v]
        for k, v in environ.items()
        if (
            k.startswith("HTTP_")
            and k not in ("HTTP_CONTENT_LENGTH", "HTTP_CONTENT_TYPE")
        )
        or k in ("CONTENT_LENGTH", "CONTENT_TYPE")
    ]


def _calc_client(environ: dict[str, bytes]) -> list[Any] | None:
    """
    Generate the ``client`` key for the ASGI scope.

    :param environ: The CGI environment dictionary.
    :returns: A two-element list of client hostname and port number, or ``None`` if the
        information is not available.
    """
    addr = environ.get("REMOTE_ADDR")
    port = environ.get("REMOTE_PORT")  # Nonstandard, but may exist
    if addr is not None and port is not None:
        try:
            return [addr.decode("UTF-8"), int(port)]
        except UnicodeDecodeError:
            logging.getLogger(__name__).error("REMOTE_ADDR %s is not valid UTF-8", addr)
            return None
    else:
        return None


def _calc_status(status: int) -> str:
    """
    Generate the HTTP status string.

    :param status: The status code.
    :returns: The status line including the reason phrase.
    """
    try:
        phrase = http.HTTPStatus(status).phrase
    except ValueError:
        phrase = "Unknown Status"
    return f"{status} {phrase}"


class _Instance:
    """The handler for one accepted connection."""

    __slots__ = {
        "_application": """The application callable.""",
        "_read_cb": """The read-from-client callable.""",
        "_write_cb": """The write-to-client callable.""",
        "_base_uri": """The base URI prefix.""",
        "_disconnected": """Whether the SCGI connection has been closed.""",
        "_request_ended": """Whether the end of the request has been received.""",
        "_reader": """The SCGI protocol request state machine.""",
        "_writer": """The SCGI protocol response state machine.""",
        "_response_headers": """The response headers provided by the application.""",
        "_response_headers_sent": """Whether the response headers have been sent.""",
        "_state": """The application state dictionary.""",
    }

    _application: ApplicationType
    _read_cb: Callable[[], Awaitable[bytes]]
    _write_cb: Callable[[bytes, bool], Awaitable[None]]
    _base_uri: str | None
    _disconnected: bool
    _request_ended: bool
    _reader: sioscgi.request.SCGIReader
    _writer: sioscgi.response.SCGIWriter
    _response_headers: sioscgi.response.Headers | None
    _response_headers_sent: bool
    _state: dict[Any, Any]

    def __init__(
        self: _Instance,
        application: ApplicationType,
        read_cb: Callable[[], Awaitable[bytes]],
        write_cb: Callable[[bytes, bool], Awaitable[None]],
        base_uri: str | None,
        state: dict[Any, Any],
    ) -> None:
        """
        Construct a new _Instance.

        :param application: The application callable.
        :param read_cb: The read-from-client callable.
        :param write_cb: The write-to-client callable.
        :param base_uri: The request URI prefix to the base of the application for
            computing root_path and path, or None to use SCRIPT_NAME and PATH_INFO
            instead.
        :param state: The state dictionary that the application can use.
        """
        self._application = application
        self._read_cb = read_cb
        self._write_cb = write_cb
        self._base_uri = base_uri
        self._disconnected = False
        self._request_ended = False
        self._reader = sioscgi.request.SCGIReader()
        self._writer = sioscgi.response.SCGIWriter()
        self._response_headers = None
        self._response_headers_sent = False
        self._state = state

    async def run(self: _Instance) -> None:
        """Run the application."""
        # Receive the request line and headers from the SCGI client.
        environ: dict[str, bytes] | None = None
        while environ is None:
            event = self._reader.next_event()
            if event is None:
                chunk = await self._read_chunk()
                if chunk:
                    self._reader.receive_data(chunk)
                else:
                    # EOF before headers are finished. Abandon the request.
                    return
            else:
                # Got a complete event. The first received event should be the request
                # headers.
                assert isinstance(event, sioscgi.request.Headers)
                environ = event.environment

        # Uppercase keys in the environment (the CGI specification states that they are
        # case-insensitive, and this makes subsequent code easier).
        environ = {k.upper(): v for k, v in environ.items()}

        # Figure out paths.
        if self._base_uri is not None:
            # A base path was given explicitly. The request URI must begin with the base
            # path (otherwise the request cannot be handled), and root_path should be
            # the given base path while path should be the entire request URI. This form
            # is useful for HTTP servers that don’t set SCRIPT_NAME and PATH_INFO
            # properly.
            request_uri = environ["REQUEST_URI"]
            try:
                path = request_uri.decode("UTF-8")
            except UnicodeDecodeError:
                logging.getLogger(__name__).error(
                    "REQUEST_URI %s is not valid UTF-8", request_uri
                )
                return
            if not path.startswith(self._base_uri):
                logging.getLogger(__name__).error(
                    'REQUEST_URI "%s" does not start with specified base URI "%s"',
                    path,
                    self._base_uri,
                )
                return
            root_path = self._base_uri
        else:
            # No base path was given. The HTTP server is to be trusted to break down the
            # request into a part designating the application (called SCRIPT_NAME in CGI
            # and root_path in ASGI) and a part designating an entity within the
            # application (called PATH_INFO in CGI, and the portion of path following
            # root_path in ASGI).
            script_name = environ["SCRIPT_NAME"]
            try:
                root_path = script_name.decode("UTF-8")
            except UnicodeDecodeError:
                logging.getLogger(__name__).error(
                    "SCRIPT_NAME %s is not valid UTF-8", script_name
                )
                return
            path_info = environ.get("PATH_INFO", b"")
            try:
                path = root_path + path_info.decode("UTF-8")
            except UnicodeDecodeError:
                logging.getLogger(__name__).error(
                    "PATH_INFO %s is not valid UTF-8", path_info
                )
                return

        # UTF-8-decode the REQUEST_METHOD and SERVER_NAME fields.
        request_method = environ["REQUEST_METHOD"]
        try:
            request_method_str = request_method.decode("UTF-8")
        except UnicodeDecodeError:
            logging.getLogger(__name__).error(
                "REQUEST_METHOD %s is invalid UTF-8", request_method
            )
            return
        server_name = environ["SERVER_NAME"]
        try:
            server_name_str = server_name.decode("UTF-8")
        except UnicodeDecodeError:
            logging.getLogger(__name__).error(
                "SERVER_NAME %s is invalid UTF-8", server_name
            )
            return

        # Build a scope dictionary.
        scope: EventOrScope = {
            "type": "http",
            "asgi": {
                "version": "3.0",
                "spec_version": "2.3",
            },
            "http_version": _calc_http_version(environ["SERVER_PROTOCOL"]),
            "method": request_method_str.upper(),
            "scheme": _guess_scheme(environ),
            "path": path,
            "query_string": environ["QUERY_STRING"],
            "root_path": root_path,
            "headers": _calc_http_headers(environ),
            "client": _calc_client(environ),
            "server": [server_name_str, int(environ["SERVER_PORT"])],
            "extensions": {
                "environ": environ,
            },
            "state": self._state,
        }

        # Run the application.
        logging.getLogger(__name__).debug("Starting application with scope %s", scope)
        await self._application(scope, self._receive, self._send)

    async def _receive(self: _Instance) -> EventOrScope:
        """Receive the next event from the SCGI client to the application."""
        if self._disconnected:
            # The connection has already disconnected.
            logging.getLogger(__name__).debug("receive called after disconnect")
            return {"type": "http.disconnect"}
        if self._request_ended:
            # Asking for another event after the request body is complete can only mean
            # one thing: wait for the connection to close and return http.disconnect.
            # This might be useful as part of a wait-for-any scheme where the
            # application wants to wait for either some external event or the client to
            # disconnect, for long polling.
            logging.getLogger(__name__).debug(
                "receive called after end of request: wait for disconnect"
            )
            await self._read_chunk()
            self._disconnected = True
            return {"type": "http.disconnect"}
        while True:
            # Try to get an event from sioscgi.
            try:
                event = self._reader.next_event()
            except sioscgi.request.Error:
                self._request_ended = True
                self._disconnected = True
                logging.getLogger(__name__).error(
                    "SCGI remote protocol error", exc_info=True
                )
                return {"type": "http.disconnect"}
            if event is not None:
                # Translate the event into an ASGI event.
                assert isinstance(event, sioscgi.request.Body | sioscgi.request.End)
                if isinstance(event, sioscgi.request.Body):
                    return {
                        "type": "http.request",
                        "body": event.data,
                        "more_body": True,
                    }
                self._request_ended = True
                return {"type": "http.request"}
            # No more events available. Read bytes from the SCGI socket.
            raw = await self._read_chunk()
            self._reader.receive_data(raw)
            if not raw:
                self._request_ended = True
                self._disconnected = True
                logging.getLogger(__name__).debug("Premature EOF on SCGI socket")
                return {"type": "http.disconnect"}

    async def _send(self: _Instance, event: EventOrScope) -> None:
        event_type = event["type"]
        if event_type == "http.response.start":
            assert self._response_headers is None
            status_code = event["status"]
            assert isinstance(status_code, int)
            headers = event["headers"]
            assert isinstance(headers, list)
            self._response_headers = sioscgi.response.Headers(
                _calc_status(status_code),
                [(k.decode("ISO-8859-1"), v.decode("ISO-8859-1")) for k, v in headers],
            )
        elif event_type == "http.response.body":
            await self._send_headers()
            body = event.get("body")
            if body:  # is present, not None, and nonzero length
                assert isinstance(body, bytes)
                await self._send_event(sioscgi.response.Body(body), drain=True)
            if not event.get("more_body", False):
                await self._send_event(sioscgi.response.End(), drain=True)
        else:
            msg = f"Unknown event type {event_type!r} passed to send"
            raise ValueError(msg)

    async def _read_chunk(self: _Instance) -> bytes:
        """Read the next chunk from the SCGI client."""
        try:
            return await self._read_cb()
        except ConnectionResetError:
            return b""

    async def _send_headers(self: _Instance) -> None:
        """Send the headers to the SCGI client, if not already been sent."""
        if not self._response_headers_sent:
            # We must have some headers to send.
            if self._response_headers is None:
                msg = "http.response.start never sent"
                raise ValueError(msg)

            # Send the headers, but don’t drain the connection; allow the I/O layer to
            # optimize by concatenating the headers and the first body chunk into a
            # single OS call if it wishes.
            await self._send_event(self._response_headers, drain=False)

            self._response_headers_sent = True

    async def _send_event(
        self: _Instance, event: sioscgi.response.Event, drain: bool
    ) -> None:
        """Send an event to the SCGI client."""
        raw = self._writer.send(event)
        # If disconnected, silently discard (ASGI says so).
        if raw and not self._disconnected:
            try:
                await self._write_cb(raw, drain)
            except (BrokenPipeError, ConnectionResetError):
                # ASGI spec says send on closed connection must be no-op.
                logging.getLogger(__name__).debug("SCGI socket broken on write")
                self._disconnected = True


class Container:
    """An ASGI container."""

    __slots__ = {
        "_base_uri": """The base URI prefix.""",
    }

    _base_uri: str | None

    def __init__(self: Container, base_uri: str | None) -> None:
        """
        Construct a new ASGI container.

        :param base_uri: The request URI prefix to the base of the application for
            computing root_path and path, or None to use SCRIPT_NAME and PATH_INFO
            instead.
        """
        self._base_uri = base_uri

    def run(
        self: Container,
        application: ApplicationType,
        read_cb: Callable[[], Awaitable[bytes]],
        write_cb: Callable[[bytes, bool], Awaitable[None]],
        state: dict[Any, Any],
    ) -> Awaitable[None]:
        """
        Run the application to handle one client connection.

        Any exceptions raised by application are propagated to the caller.

        The caller is expected to close the connection to the SCGI client after this
        function returns.

        :param application: The application callable.
        :param read_cb: A coroutine which accepts no parameters and, when called,
            returns a bytes received from the SCGI client, or an empty bytes if the SCGI
            client has closed the connection.
        :param write_cb: A coroutine which accepts a bytes and a bool as a parameter
            and, when called, sends the bytes to the SCGI client; the bool is a hint
            indicating whether the coroutine should wait until the bytes have been sent
            before returning.
        :param state: The state dictionary that the application can use.
        """
        i = _Instance(application, read_cb, write_cb, self._base_uri, state)
        return i.run()
