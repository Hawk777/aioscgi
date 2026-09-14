"""An ASGI container."""

from __future__ import annotations

from typing import Any

from .types import ApplicationType


class Container:
    """
    An ASGI container.

    There should be one instance of this for an entire server, event loop, or similar
    entity.
    """

    __slots__ = {
        "application": "The application callable.",
        "base_uri": "The base URI prefix.",
        "state": "The application state dictionary.",
        "x_sendfile": "Whether to enable http.response.pathsend via X-Sendfile.",
    }

    application: ApplicationType
    base_uri: str | None
    state: dict[Any, Any]
    x_sendfile: bool

    def __init__(
        self,
        application: ApplicationType,
        base_uri: str | None,
        *,
        x_sendfile: bool = False,
    ) -> None:
        """
        Construct a new ASGI container.

        :param application: The application callable.
        :param base_uri: The request URI prefix to the base of the application for
            computing root_path and path, or None to use SCRIPT_NAME and PATH_INFO
            instead.
        :param x_sendfile: Whether to enable http.response.pathsend via X-Sendfile.
        """
        self.application = application
        self.base_uri = base_uri
        self.state = {}
        self.x_sendfile = x_sendfile
