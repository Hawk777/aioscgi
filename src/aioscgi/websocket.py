"""The WebSocket protocol."""

import contextlib
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from typing import Never, cast

with contextlib.suppress(ImportError):
    import wsproto
    import wsproto.events
    import wsproto.handshake
    import wsproto.utilities

from .container import Container
from .types import EventOrScope, Socket

_TCHAR = set(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
)
"""The characters that can be part of a token."""


def _is_token(x: bytes) -> bool:
    """Check whether a given byte sequence is a token."""
    return all(c in _TCHAR for c in x)


class _ConnectionClosedError(BrokenPipeError):
    """Raised from the send function if the HTTP connection was closed by the peer."""


class _Connection:
    """The handler for one accepted connection."""

    __slots__ = {
        "_accepted_or_rejected_notify": "Notifies of acceptance or rejection.",
        "_accepted_or_rejected_wait": "Waits until acceptance or rejection.",
        "_container": "The ASGI container.",
        "_handshake": "The HTTP/1.1 handshake.",
        "_never": "An awaitable that will never complete.",
        "_read_eof": "Whether, in the read direction, the connection has been closed.",
        "_receive_iter": "An asynchronous iterator over the received events.",
        "_receive_mutex": "A mutex held by whatever task is currently reading.",
        "_rejected": "Whether the request was rejected.",
        "_scope": "The scope.",
        "_socket": "The socket.",
        "_started": "Whether the websocket.connect event has been received.",
    }

    _accepted_or_rejected_notify: Callable[[], None]
    _accepted_or_rejected_wait: Callable[[], Awaitable[None]]
    _container: Container
    _handshake: wsproto.handshake.H11Handshake
    _never: Callable[[], Awaitable[Never]]
    _read_eof: bool
    _receive_iter: AsyncGenerator[EventOrScope]
    _receive_mutex: AbstractAsyncContextManager[None]
    _rejected: bool
    _scope: EventOrScope
    _socket: Socket
    _started: bool

    def __init__(
        self,
        container: Container,
        handshake: wsproto.handshake.H11Handshake,
        scope: EventOrScope,
        socket: Socket,
    ) -> None:
        """
        Construct a new _Connection.

        :param container: The ASGI container.
        :param handshake: The HTTP/1.1 handshake.
        :param scope: The scope.
        :param socket: The socket.
        """
        (
            self._accepted_or_rejected_notify,
            self._accepted_or_rejected_wait,
        ) = socket.create_one_shot()
        self._container = container
        self._handshake = handshake
        self._never = socket.create_one_shot()[1]
        self._read_eof = False
        self._receive_iter = self._receive_gen()
        self._receive_mutex = socket.create_mutex()
        self._rejected = False
        self._scope = scope
        self._socket = socket
        self._started = False

    async def run(self) -> None:
        """Run the connection."""
        logger = logging.getLogger(__name__)
        logger.debug("Starting application with scope %s", self._scope)
        try:
            await self._container.application(self._scope, self._receive, self._send)
        except _ConnectionClosedError:
            pass
        except Exception:  # pylint: disable=broad-except
            logger.exception("Uncaught exception in application callable")
        finally:
            logger.debug("Closing receive generator")
            await self._receive_iter.aclose()
            logger.debug("Receive generator closed")

    async def _receive_gen(self) -> AsyncGenerator[EventOrScope]:
        """Yield all the receive events."""
        yield {"type": "websocket.connect"}
        await self._accepted_or_rejected_wait()
        if self._rejected:
            yield {"type": "websocket.disconnect", "code": 1007}
            await self._never()
        conn = self._handshake.connection
        assert conn is not None
        while True:
            for e in conn.events():
                logging.getLogger(__name__).debug("wsproto event %r", e)
            chunk = await self._socket.read_chunk()
            conn.receive_data(chunk or None)
NOT_DONE_YET

    async def _receive(self) -> EventOrScope:
        """Receive the next event from the SCGI client to the application."""
        async with self._receive_mutex:
            return await anext(self._receive_iter)

    async def _send(self, event: EventOrScope) -> None:
        """Send an event to the SCGI client."""
NOT_DONE_YET
        event_type = event["type"]
        assert isinstance(event_type, str)
        match event_type:
            case "websocket.accept":
                await self._send_accept(event)
            case "websocket.send":
                raise NotImplementedError
            case "websocket.close":
                raise NotImplementedError
            case "websocket.http.response.start":
                raise NotImplementedError
            case "websocket.http.response.body":
                raise NotImplementedError
            case _:
                msg = f"Invalid event type {event_type}"
                raise ValueError(msg)

    async def _send_accept(self, event: EventOrScope) -> None:
        """Send a websocket.accept event to the SCGI client."""
        subprotocol = event.get("subprotocol")
        assert isinstance(subprotocol, str | None)
        headers = event.get("headers", [])
        assert isinstance(headers, list)
        assert all(isinstance(k, bytes) and isinstance(v, bytes) for (k, v) in headers)
        assert all(k.islower() for (k, _) in headers)
        assert all(k != b"sec-websocket-protocol" for (k, _) in headers)
        e = wsproto.events.AcceptConnection(
            subprotocol=subprotocol,
            extra_headers=headers,
        )
        b = self._handshake.send(e)
        self._accepted_or_rejected_notify()
        self._socket.write_chunk(b)
        await self._socket.drain_write()


async def run(
    container: Container,
    socket: Socket,
    scope: EventOrScope,
) -> bool:
    """
    Handle an SCGI connection.

    :param container: The ASGI container.
    :param socket: The incoming connected socket.
    :param scope: The scope dictionary constructed by the HTTP layer, which will either
        be left unmodified or False is returned, or may be modified for this module’s
        own use if True is returned.
    :return: True if the request was a WebSocket request which has been handled and the
        application has terminated, or False if the request is a non-WebSocket request
        which should be handled by the HTTP layer.
    """
    # Grab the environment.
    extensions = cast("dict[str, EventOrScope]", scope["extensions"])
    environ = cast("dict[str, bytes]", extensions["environ"])

    # Check these two requirements from RFC6455 that are not checked by wsproto because
    # the relevant information is not passed to H11Handshake.
    if scope["method"] != "GET":
        return False
    if scope["http_version"] == "1.0":
        return False

    # Convert the environment array back into a collection of headers to pass to
    # wsproto.
    headers = [
        (k.removeprefix("HTTP_").replace("_", "-").encode("UTF-8"), v)
        for (k, v) in environ.items()
        if k.startswith("HTTP_") or k in {"CONTENT_LENGTH", "CONTENT_TYPE"}
    ]

    # Set up an HTTP/1.1-style handshake completion.
    handshake = wsproto.handshake.H11Handshake(wsproto.ConnectionType.SERVER)
    try:
        handshake.initiate_upgrade_connection(headers, cast("str", scope["path"]))
    except wsproto.utilities.RemoteProtocolError:
        # This isn’t a valid WebSocket request. We don’t know whether it was *supposed*
        # to be, or whether the client intended it to just be a regular HTTP request.
        # So, instead of rejecting out of hand, just return False and let it be handled
        # as an HTTP request instead. That’s compliant with the HTTP spec: the Upgrade
        # header is the protocols the client is *willing* to be upgraded to, and the
        # server is allowed to decide not to.
        return False

    # There should be a Request event.
    request = next(handshake.events())
    assert isinstance(request, wsproto.events.Request)

    # Update the scope.
    scope["type"] = "websocket"
    scope["scheme"] = {"http": "ws", "https": "wss"}[cast("str", scope["scheme"])]
    if request.subprotocols:
        scope["subprotocols"] = request.subprotocols
    scope["extensions"] = {"environ": environ}

    # Run.
    await _Connection(container, handshake, scope, socket).run()
    return True
