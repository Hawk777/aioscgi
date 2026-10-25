"""The HTTP protocol."""

from __future__ import annotations

import functools
import http
import logging
import urllib.parse
import wsgiref.util
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Mapping
from contextlib import AbstractAsyncContextManager, aclosing, closing
from typing import Any

import sioscgi.request
import sioscgi.response

from .container import Container
from .types import Adapter, EventOrScope, Socket


class _ConnectionClosedError(BrokenPipeError):
    """Raised from send if the HTTP connection was closed by the peer."""

    __slots__ = ()


class _ReceiveAfterAppEndsError(Exception):
    """Raised from receive if called after the application coroutine ends."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("receive function called after application coroutine ended")


class _ReceiveAfterDisconnectError(Exception):
    """Raised from receive if called again after returning http.disconnect."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("receive function called after returning http.disconnect")


class _SendAfterAppEndsError(Exception):
    """Raised from send if called after the application coroutine ends."""

    __slots__ = {
        "event": "The event that was erroneously sent.",
    }

    event: str

    def __init__(self, event: str) -> None:
        super().__init__(
            f"send called with event type “{event}” after application coroutine ended",
        )
        self.event = event


class _SendAfterLastError(Exception):
    """Raised from send if called again after what should have been the last event."""

    __slots__ = {
        "cur_event": "The event that was erroneously sent.",
        "prev_event": "The previous event that should have been the last one.",
    }

    cur_event: str
    prev_event: str

    def __init__(self, cur_event: str, prev_event: str) -> None:
        super().__init__(
            f"send called with event type “{cur_event}”, expected previous event of "
            f"type “{prev_event}” to be the last one",
        )
        self.cur_event = cur_event
        self.prev_event = prev_event


class _SendAfterErrorError(Exception):
    """Raised from send if called again after a previous call failed."""

    __slots__ = {
        "event": "The event that was erroneously sent.",
    }

    event: str

    def __init__(self, event: str) -> None:
        super().__init__(
            f"send called with event type “{event}” after previously raising an "
            "exception"
        )
        self.event = event


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
            and k not in {"HTTP_CONTENT_LENGTH", "HTTP_CONTENT_TYPE"}
        )
        or k in {"CONTENT_LENGTH", "CONTENT_TYPE"}
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
            logging.getLogger(__name__).exception(
                "REMOTE_ADDR %s is not valid UTF-8",
                addr,
            )
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


def _make_scope(
    container: Container,
    environ: Mapping[str, bytes],
) -> EventOrScope | None:
    """
    Convert a CGI/SCGI environment mapping into an ASGI HTTP scope dictionary.

    :param container: The ASGI container.
    :param environ: The CGI/SCGI environment mapping.
    :return: The HTTP scope, or None if the request is malformed, in which case an error
        has been logged and the caller should not run the ASGI application.
    """
    # Uppercase keys in the environment (the CGI specification states that they are
    # case-insensitive, and this makes subsequent code easier).
    environ = {k.upper(): v for k, v in environ.items()}

    # Figure out paths.
    if container.base_uri is not None:
        # A base path was given explicitly. The request URI must begin with the base
        # path (otherwise the request cannot be handled), and root_path should be
        # the given base path while path should be the entire request URI. This form
        # is useful for HTTP servers that don’t set SCRIPT_NAME and PATH_INFO
        # properly.
        request_uri = environ["REQUEST_URI"]
        try:
            path = request_uri.decode("UTF-8")
        except UnicodeDecodeError:
            logging.getLogger(__name__).exception(
                "REQUEST_URI %s is not valid UTF-8",
                request_uri,
            )
            return None
        if not path.startswith(container.base_uri):
            logging.getLogger(__name__).error(
                'REQUEST_URI "%s" does not start with specified base URI "%s"',
                path,
                container.base_uri,
            )
            return None
        root_path = container.base_uri
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
            logging.getLogger(__name__).exception(
                "SCRIPT_NAME %s is not valid UTF-8",
                script_name,
            )
            return None
        path_info = environ.get("PATH_INFO", b"")
        try:
            path = root_path + path_info.decode("UTF-8")
        except UnicodeDecodeError:
            logging.getLogger(__name__).exception(
                "PATH_INFO %s is not valid UTF-8",
                path_info,
            )
            return None

    # UTF-8-decode the REQUEST_METHOD and SERVER_NAME fields.
    request_method = environ["REQUEST_METHOD"]
    try:
        request_method_str = request_method.decode("UTF-8")
    except UnicodeDecodeError:
        logging.getLogger(__name__).exception(
            "REQUEST_METHOD %s is invalid UTF-8",
            request_method,
        )
        return None
    server_name = environ["SERVER_NAME"]
    try:
        server_name_str = server_name.decode("UTF-8")
    except UnicodeDecodeError:
        logging.getLogger(__name__).exception(
            "SERVER_NAME %s is invalid UTF-8",
            server_name,
        )
        return None

    # Build a scope dictionary.
    return {
        "type": "http",
        "asgi": {
            "version": "3.0",
            "spec_version": "2.5",
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
            **({"http.response.pathsend": {}} if container.x_sendfile else {}),
        },
        "state": container.state,
    }


class _Connection:
    """
    The handler for one accepted connection.

    Each time the I/O adapter accepts a new incoming connection, it must create a new
    instance of an I/O-adapter-specific subclass of this class (in a common task or in a
    dedicated per-connection task) and then await the object’s run method (in a
    dedicated per-connection task).
    """

    __slots__ = {
        "_container": "The ASGI container.",
        "_disconnected_set": "A callable that sets the disconnected event.",
        "_disconnected_wait": "A callable that waits for the disconnected event.",
        "_read_error": "The error that previously occurred while reading, if any.",
        "_reader": "The SCGI protocol request state machine.",
        "_reader_mutex": "A mutex held by the task calling _receive.",
        "_socket": "The socket.",
        "_write_error": "The error that previously occurred while writing, if any.",
        "_writer": "The SCGI protocol response state machine.",
    }

    _container: Container
    _disconnected_set: Callable[[], None]
    _disconnected_wait: Callable[[], Awaitable[None]]
    _read_error: Exception | None
    _reader: sioscgi.request.SCGIReader
    _reader_mutex: AbstractAsyncContextManager[None]
    _socket: Socket
    _write_error: Exception | None
    _writer: sioscgi.response.SCGIWriter

    def __init__(self, container: Container, adapter: Adapter, socket: Socket) -> None:
        """
        Construct a new _Connection.

        :param container: The ASGI container.
        :param adapter: The I/O adapter.
        :param socket: The incoming connected socket.
        """
        self._container = container
        (self._disconnected_set, self._disconnected_wait) = adapter.create_event()
        self._read_error = None
        self._reader = sioscgi.request.SCGIReader()
        self._reader_mutex = adapter.create_mutex()
        self._socket = socket
        self._write_error = None
        self._writer = sioscgi.response.SCGIWriter()

    async def run(self) -> None:
        """
        Run the application.

        The caller is expected to close the connection to the SCGI client after this
        function returns.
        """
        # Receive the request line and headers from the SCGI client.
        environ: dict[str, bytes] | None = None
        while environ is None:
            try:
                event = self._reader.next_event()
            except sioscgi.request.Error:
                logging.getLogger(__name__).exception("SCGI remote protocol error")
                return
            if event is None:
                try:
                    chunk = await self._socket.read_chunk()
                except ConnectionResetError:
                    # RST before headers are finished. Abandon the request.
                    return
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

        # Build a scope dictionary.
        scope: EventOrScope | None = _make_scope(self._container, environ)
        if scope is None:
            return

        # Run the application.
        with closing(self._send_gen()) as send_gen:
            next(send_gen)  # Advance to the first yield expression.
            async with aclosing(self._receive_gen()) as receive_gen:
                logging.getLogger(__name__).debug(
                    "Starting application with scope %s",
                    scope,
                )
                try:
                    await self._container.application(
                        scope,
                        functools.partial(self._receive, receive_gen),
                        functools.partial(self._send, send_gen),
                    )
                except _ConnectionClosedError:
                    pass
                except Exception:  # pylint: disable=broad-except
                    logging.getLogger(__name__).exception(
                        "Uncaught exception in application callable",
                    )

    async def _receive_next_event(self) -> sioscgi.request.Event:
        """
        Receive the next sioscgi event.

        This method must not be called after it has returned sioscgi.request.End.

        :return: The event.
        """
        while (event := self._reader.next_event()) is None:
            try:
                chunk = await self._socket.read_chunk()
            except ConnectionResetError:
                chunk = b""
            self._reader.receive_data(chunk)
        return event

    async def _receive_gen(self) -> AsyncGenerator[EventOrScope]:
        """
        Yield the events that the application should receive.

        The generator will yield as many legitimate events as possible, then raise an
        exception indicating that either a protocol or I/O error occurred or that the
        application is asking for another event when it shouldn’t.
        """
        # Ship events from sioscgi until reaching End.
        try:
            while True:
                event = await self._receive_next_event()
                assert isinstance(event, sioscgi.request.Body | sioscgi.request.End)
                if isinstance(event, sioscgi.request.Body):
                    yield {
                        "type": "http.request",
                        "body": event.data,
                        "more_body": True,
                    }
                else:
                    yield {"type": "http.request"}
                    break
        except sioscgi.request.Error as exp:
            if isinstance(exp, sioscgi.request.RemotePrematureEOFError):
                # This is not really an error, it just indicates the SCGI client is no
                # longer interested in this request.
                logging.getLogger(__name__).debug("Premature EOF on SCGI socket")
            else:
                logging.getLogger(__name__).exception("SCGI remote protocol error")
            yield {"type": "http.disconnect"}
            raise _ReceiveAfterDisconnectError from None

        # After the end of the body, receiving again just waits until the connection is
        # closed and then returns http.disconnect.
        await self._disconnected_wait()
        yield {"type": "http.disconnect"}
        raise _ReceiveAfterDisconnectError

    async def _receive(self, gen: AsyncGenerator[EventOrScope]) -> EventOrScope:
        """
        Receive the next event from the SCGI client to the application.

        :param gen: The generator that yields events.
        """
        async with self._reader_mutex:
            if self._read_error is not None:
                raise self._read_error
            try:
                return await anext(gen)
            except StopAsyncIteration:
                raise _ReceiveAfterAppEndsError from None
            except Exception as exp:
                self._read_error = exp
                raise

    def _send_events(self, *events: sioscgi.response.Event) -> None:
        """Send one or more events to the SCGI client."""
        events_bytes = (self._writer.send(i) for i in events)
        raw = b"".join(i for i in events_bytes if i is not None)
        if raw:
            self._socket.write_chunk(raw)

    @staticmethod
    def _send_unpack_start(event: EventOrScope) -> tuple[int, list[tuple[str, str]]]:
        """
        Check and unpack an event of type “http.response.start”.

        :param event: The event from the application.
        :return: The HTTP status code and response headers.
        """
        event_type = event["type"]
        assert isinstance(event_type, str)
        if event_type != "http.response.start":
            msg = f"App sent event “{event_type}”, expected “http.response.start”"
            raise ValueError(msg)
        if "trailers" in event:
            msg = "trailers are not supported via SCGI"
            raise ValueError(msg)
        status_code = event["status"]
        if not isinstance(status_code, int):
            msg = f"status key is of type {type(status_code)}, expected int"
            raise TypeError(msg)
        app_headers = event["headers"]
        if not isinstance(app_headers, list):
            msg = f"headers key is of type {type(app_headers)}, expected list"
            raise TypeError(msg)
        str_headers = (
            (k.decode("ISO-8859-1"), v.decode("ISO-8859-1")) for k, v in app_headers
        )
        # The ASGI specification says the application is allowed to send
        # Transfer-Encoding and the container is required to ignore it.
        headers = [(k, v) for k, v in str_headers if k.lower() != "transfer-encoding"]
        return (status_code, headers)

    def _send_gen(self) -> Generator[None, EventOrScope, None]:
        """
        Accept events from the application sent to the framework.

        :return: A generator that can be sent events sent by the application, and that
            either consumes them or raises an exception if they should be rejected.
        """
        # Get http.response.start. Don’t actually send anything yet, because we might
        # need to augment the headers with X-Sendfile later.
        event = yield
        (status_code, headers) = self._send_unpack_start(event)

        # Get the first body event.
        event = yield
        event_type = event["type"]
        assert isinstance(event_type, str)
        match event_type:
            case "http.response.body":
                # Send the saved headers plus the body chunk.
                data = event.get("body", b"")
                assert isinstance(data, bytes)
                self._send_events(
                    sioscgi.response.Headers(
                        _calc_status(status_code),
                        headers,
                    ),
                    sioscgi.response.Body(data),
                )
                more = event.get("more_body", False)

            case "http.response.pathsend":
                if not self._container.x_sendfile:
                    msg = (
                        "App sent event “http.response.pathsend”, but pathsend "
                        "extension (X-Sendfile option) is disabled"
                    )
                    raise ValueError(msg)
                # Add X-Sendfile to the headers and send them. http.response.pathsend
                # may not be mixed with http.response.body, so this must be the last
                # sent event.
                path = event["path"]
                assert isinstance(path, str)
                headers.append(("X-Sendfile", urllib.parse.quote(path, "")))
                self._send_events(
                    sioscgi.response.Headers(
                        _calc_status(status_code),
                        headers,
                    ),
                )
                more = False

            case _:
                expected_types = (
                    "http.response.body or http.response.pathsend"
                    if self._container.x_sendfile
                    else "http.response.body"
                )
                msg = f"App sent event “{event_type}”, expected {expected_types}"
                raise ValueError(msg)

        # Get the rest of the body events.
        while more:
            event = yield
            event_type = event["type"]
            assert isinstance(event_type, str)
            if event_type != "http.response.body":
                msg = f"App sent event “{event_type}”, expected http.response.body"
                raise ValueError(msg)
            data = event.get("body", b"")
            assert isinstance(data, bytes)
            self._send_events(sioscgi.response.Body(data))
            more = event.get("more_body", False)

        # The response body is done so close the connection.
        self._send_events(sioscgi.response.End())
        self._disconnected_set()

        # There shouldn’t be any more events now, so if there are, report an error.
        erroneous_event = yield
        erroneous_type = erroneous_event["type"]
        assert isinstance(erroneous_type, str)
        raise _SendAfterLastError(erroneous_type, event_type)

    async def _drain_write(self) -> None:
        """Wait until enough previously written data has been passed to the OS."""
        try:
            await self._socket.drain_write()
        except (BrokenPipeError, ConnectionResetError) as exp:
            logging.getLogger(__name__).debug("SCGI socket broken on write")
            raise _ConnectionClosedError from exp

    async def _send(
        self,
        gen: Generator[None, EventOrScope, None],
        event: EventOrScope,
    ) -> None:
        """
        Send the next event from the application to the SCGI client.

        :param gen: The generator that handles events.
        :param event: The event from the application.
        """
        if self._write_error is not None:
            raise self._write_error
        try:
            try:
                gen.send(event)
            except StopIteration:
                event_type = event["type"]
                assert isinstance(event_type, str)
                raise _SendAfterAppEndsError(event_type) from None
            await self._drain_write()
        except Exception as exp:
            if self._write_error is None:
                self._write_error = exp
            self._disconnected_set()
            raise


async def run(container: Container, adapter: Adapter, socket: Socket) -> None:
    """
    Handle an SCGI connection.

    :param container: The ASGI container.
    :param adapter: The I/O adapter.
    :param socket: The incoming connected socket.
    """
    return await _Connection(container, adapter, socket).run()
