"""Handling of TCP endpoint addresses."""

from typing import Self


class TCPAddress:
    """A TCP endpoint address that can be used for connecting or listening."""

    __slots__ = {
        "host": "The host part, which can be a hostname or address literal.",
        "port": "The port part, which can be a service name or integer literal.",
    }

    host: str
    port: str

    def __init__(self: Self, combined: str) -> None:
        """
        Parse a TCP listening address into host and port parts.

        :param combined: The combined string.
        """
        # The host and port part are separated by the last colon.
        parts = combined.rsplit(":", 1)
        if len(parts) != 2:
            # No colon is present.
            msg = "Missing :PORT part"
            raise ValueError(msg)
        self.host, self.port = parts
        if "[" in self.port or "]" in self.port:
            # A colon is present, but not *after* the last bracket. That probably comes
            # from an IPv6 literal without a port number, in which “[a:b:c]” is split
            # into “[a:b” and “c]”.
            msg = "Missing :PORT part"
            raise ValueError(msg)
        if self.host[0] == "[" and self.host[-1] == "]":
            # This is an IPv6 literal with brackets to isolate it from the port number.
            # The Python stdlib doesn’t like the brackets.
            self.host = self.host[1:-1]
