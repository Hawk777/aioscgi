"""The HTTP protocol."""

from __future__ import annotations

import abc
import http
import logging
import urllib.parse
import wsgiref.util
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any

import sioscgi.request
import sioscgi.response

from .container import Container
from .types import EventOrScope


class _ConnectionClosedError(BrokenPipeError):
    """Raised from the send function if the HTTP connection was closed by the peer."""


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
            "spec_version": "2.4",
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


class Connection(abc.ABC):
    """
    The handler for one accepted connection.

    Each time the I/O adapter accepts a new incoming connection, it must create a new
    instance of an I/O-adapter-specific subclass of this class (in a common task or in a
    dedicated per-connection task) and then await the object’s run method (in a
    dedicated per-connection task).
    """

    __slots__ = {
        "_container": "The ASGI container.",
        "_disconnected": "Whether the SCGI connection has been closed.",
        "_reader": "The SCGI protocol request state machine.",
        "_reader_mutex": "A mutex held by the task calling _receive.",
        "_request_ended": "Whether the end of the request has been received.",
        "_writer": "The SCGI protocol response state machine.",
        "_writer_mutex": "A mutex held by the task calling _send.",
        "_writer_pending_headers": """
            The pending response headers.

            If the application has sent http.response.start but no body content, nothing
            is sent to the SCGI client yet; instead, the response headers are held here
            until the application generates body content.
            """,
    }

    _container: Container
    _disconnected: bool
    _reader: sioscgi.request.SCGIReader
    _reader_mutex: AbstractAsyncContextManager[None]
    _request_ended: bool
    _writer: sioscgi.response.SCGIWriter
    _writer_mutex: AbstractAsyncContextManager[None]
    _writer_pending_headers: sioscgi.response.Headers | None

    def __init__(self, container: Container) -> None:
        """
        Construct a new Connection.

        :param container: The ASGI container.
        """
        self._container = container
        self._disconnected = False
        self._reader = sioscgi.request.SCGIReader()
        self._reader_mutex = self.create_mutex()
        self._request_ended = False
        self._writer = sioscgi.response.SCGIWriter()
        self._writer_mutex = self.create_mutex()
        self._writer_pending_headers = None

    @abc.abstractmethod
    def create_mutex(self) -> AbstractAsyncContextManager[None]:
        """
        Create a mutex.

        :return: An object that can be used as an asynchronous context manager, such
            that only one async task can be within the context at a time.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def read_chunk(self) -> bytes:
        """
        Read a chunk of bytes from the underlying connection.

        :return: The bytes, or a zero-length bytes object if the underlying connection
            has reached EOF.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def write_chunk(self, data: bytes, drain: bool) -> None:
        """
        Write a chunk of bytes to the underlying connection.

        :param data: The bytes to write.
        :param drain: True if the function should wait until the data has been accepted
            by the kernel before returning.
        """
        raise NotImplementedError

    async def run(self) -> None:
        """
        Run the application.

        The caller is expected to close the connection to the SCGI client after this
        function returns.
        """
        # Receive the request line and headers from the SCGI client.
        environ: dict[str, bytes] | None = None
        while environ is None:
            event = self._reader.next_event()
            if event is None:
                chunk = await self._read_chunk_wrapper()
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
        logging.getLogger(__name__).debug("Starting application with scope %s", scope)
        try:
            await self._container.application(scope, self._receive, self._send)
        except _ConnectionClosedError:
            pass
        except Exception:  # pylint: disable=broad-except
            logging.getLogger(__name__).exception(
                "Uncaught exception in application callable",
            )

    async def _receive(self) -> EventOrScope:
        """Receive the next event from the SCGI client to the application."""
        async with self._reader_mutex:
            if self._disconnected:
                # The connection has already disconnected.
                logging.getLogger(__name__).debug("receive called after disconnect")
                return {"type": "http.disconnect"}
            if self._request_ended:
                # Asking for another event after the request body is complete can only
                # mean one thing: wait for the connection to close and return
                # http.disconnect. This might be useful as part of a wait-for-any scheme
                # where the application wants to wait for either some external event or
                # the client to disconnect, for long polling.
                logging.getLogger(__name__).debug(
                    "receive called after end of request: wait for disconnect",
                )
                await self._read_chunk_wrapper()
                self._disconnected = True
                return {"type": "http.disconnect"}
            while True:
                # Try to get an event from sioscgi.
                try:
                    event = self._reader.next_event()
                except sioscgi.request.Error:
                    self._request_ended = True
                    self._disconnected = True
                    logging.getLogger(__name__).exception("SCGI remote protocol error")
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
                raw = await self._read_chunk_wrapper()
                self._reader.receive_data(raw)
                if not raw:
                    self._request_ended = True
                    self._disconnected = True
                    logging.getLogger(__name__).debug("Premature EOF on SCGI socket")
                    return {"type": "http.disconnect"}

    async def _send(self, event: EventOrScope) -> None:
        async with self._writer_mutex:
            event_type = event["type"]
            if event_type == "http.response.start":
                status_code = event["status"]
                assert isinstance(status_code, int)
                headers = event["headers"]
                assert isinstance(headers, list)
                string_headers = (
                    (k.decode("ISO-8859-1"), v.decode("ISO-8859-1")) for k, v in headers
                )
                # The ASGI specification says the application is allowed to send
                # Transfer-Encoding and the container is required to ignore it.
                filtered_headers = [
                    (k, v)
                    for k, v in string_headers
                    if k.lower() != "transfer-encoding"
                ]
                encoded = sioscgi.response.Headers(
                    _calc_status(status_code),
                    filtered_headers,
                )
                if self._writer_pending_headers is not None:
                    # We want to report the problem immediately, but really it’s an SCGI
                    # state machine error and therefore “should” be sioscgi’s job to
                    # report. However, sioscgi can’t be responsible, because we’re
                    # holding the response headers back until the first body part and
                    # therefore sioscgi never actually sees anything. Just pretend.
                    raise sioscgi.response.BadEventInStateError(
                        sioscgi.response.Headers,
                        self._writer.state,
                    )
                self._writer_pending_headers = encoded
            elif event_type == "http.response.body":
                if self._writer_pending_headers is not None:
                    await self._send_event(self._writer_pending_headers, drain=False)
                    self._writer_pending_headers = None
                body = event.get("body")
                more = event.get("more_body", False)
                assert isinstance(more, bool)
                if body:  # is present, not None, and nonzero length
                    assert isinstance(body, bytes)
                    # If more=True then drain=True now. If more=False then we’re about
                    # to drain=True in the “if not more” just below, so drain=False now
                    # and we’ll combine draining the Body and End events.
                    await self._send_event(sioscgi.response.Body(body), drain=more)
                if not more:
                    await self._send_event(sioscgi.response.End(), drain=True)
            elif event_type == "http.response.pathsend":
                if not self._container.x_sendfile:
                    msg = (
                        "Event type http.response.pathsend passed to send, but that "
                        "extension is not enabled"
                    )
                    raise ValueError(msg)
                path = event["path"]
                assert isinstance(path, str)
                if self._writer_pending_headers is None:
                    msg = (
                        "Event type http.response.pathsend passed to send without "
                        "previous http.response.start, or with previous "
                        "http.response.body"
                    )
                    raise ValueError(msg)
                old_headers = self._writer_pending_headers
                self._writer_pending_headers = None
                old_headers.other_headers["X-Sendfile"] = urllib.parse.quote(path, "")
                await self._send_event(old_headers, drain=False)
                await self._send_event(sioscgi.response.End(), drain=True)
            else:
                msg = f"Unknown event type {event_type!r} passed to send"
                raise ValueError(msg)

    async def _read_chunk_wrapper(self) -> bytes:
        """
        Read the next chunk from the SCGI client.

        A ConnectionResetError is translated into an EOF.
        """
        try:
            return await self.read_chunk()
        except ConnectionResetError:
            return b""

    async def _send_event(self, event: sioscgi.response.Event, drain: bool) -> None:
        """Send an event to the SCGI client."""
        raw = self._writer.send(event)
        if raw:
            try:
                await self.write_chunk(raw, drain)
            except (BrokenPipeError, ConnectionResetError) as exp:
                logging.getLogger(__name__).debug("SCGI socket broken on write")
                self._disconnected = True
                raise _ConnectionClosedError from exp
