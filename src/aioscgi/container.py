"""An ASGI container."""

from __future__ import annotations

from typing import Any, Self

from .types import ApplicationType


class Container:
    """
    An ASGI container.

    There should be one instance of this for an entire server, event loop, or similar
    entity.
    """

    __slots__ = {
        "application": """The application callable.""",
        "base_uri": """The base URI prefix.""",
        "state": """The application state dictionary.""",
    }

    application: ApplicationType
    base_uri: str | None
    state: dict[Any, Any]

    def __init__(
        self: Self, application: ApplicationType, base_uri: str | None
    ) -> None:
        """
        Construct a new ASGI container.

        :param application: The application callable.
        :param base_uri: The request URI prefix to the base of the application for
            computing root_path and path, or None to use SCRIPT_NAME and PATH_INFO
            instead.
        """
        self.application = application
        self.base_uri = base_uri
        self.state = {}
