"""The application entry point."""

import argparse
import importlib
import importlib.metadata
import json
import logging
import logging.config
import os
import pathlib
import socket
import sys
from collections.abc import Iterable
from typing import Self

from .container import Container
from .tcp import TCPAddress
from .types import StartStopListener


class NullaryListener(StartStopListener):
    """A start/stop listener that does nothing."""

    __slots__ = ()

    def started(self: Self) -> None:
        """Do nothing."""

    def stopping(self: Self) -> None:
        """Do nothing."""


class SystemDListener(StartStopListener):
    """A start/stop listener that notifies systemd."""

    __slots__ = {
        "_sock": "A UNIX-domain socket used to send notifications.",
        "_target": "The address to send notifications to.",
    }

    _sock: socket.socket
    _target: bytes

    def __init__(self: Self, target: bytes) -> None:
        """
        Construct a new SystemDListener.

        :param target: The UNIX-domain address to send to.
        """
        self._sock = socket.socket(
            socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC
        )
        self._target = target

    def started(self: Self) -> None:
        """Notify systemd that we have started."""
        self._send(b"READY=1")

    def stopping(self: Self) -> None:
        """Notify systemd that we are stopping."""
        self._send(b"STOPPING=1")

    def _send(self: Self, message: bytes) -> None:
        """
        Send a notification to systemd.

        :param message: The message to send.
        """
        try:
            self._sock.sendto(message, self._target)
        except OSError:
            # Failure to notify should be noted but is not fatal.
            logging.getLogger(__name__).warning(
                "systemd notification failed", exc_info=True
            )


def make_start_stop_listener(systemd: bool) -> StartStopListener:
    """
    Build the start/stop listener.

    :param systemd: True to try to use systemd notification, or False to not.
    :return: The start/stop listener to use.
    """
    if not systemd:
        # systemd integration not requested by the user.
        return NullaryListener()
    path = os.environb.get(b"NOTIFY_SOCKET")
    if path is None:
        # systemd integration requested but notification not available. This is
        # info-level because it could potentially happen under systemd when the service
        # type is set to something other than notify, which a user could have done
        # intentionally (and they might still want --systemd for other purposes).
        logging.getLogger(__name__).info(
            "systemd notification unavailable because NOTIFY_SOCKET unset"
        )
        return NullaryListener()
    if path == b"":
        # Environment variable is set but empty.
        msg = "NOTIFY_SOCKET is empty"
        raise ValueError(msg)
    if path[0] == ord(b"/"):
        # Notification socket is a filesystem-namespace socket.
        return SystemDListener(path)
    if path[0] == ord(b"@"):
        # Notification socket is an abstract-namespace socket.
        return SystemDListener(b"\x00" + path[1:])
    # Notification socket is unknown and unsupported (maybe vsock?).
    msg = f"Unrecognized NOTIFY_SOCKET value {os.fsdecode(path)}"
    raise ValueError(msg)


def find_extra_sockets(systemd: bool) -> Iterable[socket.socket]:
    """
    Find the extra already-bound sockets.

    :param systemd: True to try to use systemd socket passing, or False to not.
    :return: The discovered external sockets.
    """
    if not systemd:
        # systemd integration not requested by the user.
        return ()
    listen_pid_str = os.environ.get("LISTEN_PID")
    listen_fds_str = os.environ.get("LISTEN_FDS")
    if listen_pid_str is None or listen_fds_str is None:
        # Socket passing mechanism not used. This is info-level because the service
        # could be launched under systemd and be using integration for e.g. startup
        # notification, but not be using socket passing.
        logging.getLogger(__name__).info("No systemd sockets passed")
        return ()
    listen_pid = int(listen_pid_str)
    listen_fds = int(listen_fds_str)
    if listen_pid != os.getpid():
        # Socket passing mechanism in use for some other process whose environment
        # variable we inherited, but not intended for us.
        logging.getLogger(__name__).info("No systemd sockets passed")
        return ()
    socks = [socket.socket(fileno=i) for i in range(3, 3 + listen_fds)]
    for sock in socks:
        os.set_inheritable(sock.fileno(), False)  # noqa: FBT003
    logging.getLogger(__name__).info("%d systemd socket(s) passed", len(socks))
    return socks


def main() -> None:
    """Run the application."""
    try:
        # Discover the available I/O adapters.
        io_adapters = {
            entry.name: entry
            for entry in importlib.metadata.entry_points(group="aioscgi.io")
        }

        # Parse and check command-line parameters.
        parser = argparse.ArgumentParser(
            description="Run an ASGI application under asyncio."
        )
        parser.add_argument(
            "--adapter",
            default="asyncio",
            choices=io_adapters,
            help="the I/O adapter to use (default: asyncio)",
        )
        parser.add_argument(
            "--base-uri",
            type=str,
            help="the request URI prefix to the base of the application for computing "
            "root_path and path (default: use SCRIPT_NAME and PATH_INFO instead)",
        )
        parser.add_argument(
            "--logging",
            "-l",
            type=pathlib.Path,
            help="the JSON file containing a logging configuration dictionary per "
            "logging.config.dictConfig (default: none)",
        )
        parser.add_argument(
            "--unix-socket",
            "-u",
            action="append",
            default=[],
            type=pathlib.Path,
            help="the UNIX socket path to listen on",
        )
        parser.add_argument(
            "--tcp",
            "-t",
            action="append",
            default=[],
            type=TCPAddress,
            help="the TCP address/port to listen on",
            metavar="IPv4ADDR:PORT | [IPv6ADDR]:PORT | HOSTNAME:PORT",
        )
        parser.add_argument(
            "--systemd",
            action="store_true",
            help="enable systemd integration (startup notification, socket passing)",
        )
        parser.add_argument(
            "application", help="the dotted.module.name:callable of the application"
        )
        args = parser.parse_args()
        if not any((args.unix_socket, args.tcp, args.systemd)):
            parser.error(
                "At least one of --unix-socket, --tcp, or --systemd must be supplied."
            )

        # Set up logging.
        if args.logging is not None:
            with args.logging.open("rb") as logging_config_file:
                cfg = json.load(logging_config_file)
            logging.config.dictConfig(cfg)
        else:
            logging.basicConfig(level=logging.INFO)

        # Find any externally provided sockets.
        extra_sockets = find_extra_sockets(args.systemd)

        # Make sure we have any listeners at all.
        if not any((args.unix_socket, args.tcp, extra_sockets)):
            parser.error(
                "With only --systemd and not --unix-socket or --tcp, at least one "
                "socket must be passed by systemd."
            )

        # Load the I/O adapter.
        adapter = io_adapters[args.adapter].load()

        # Import the application module and find the callable.
        sys.path.insert(0, ".")
        app_parts = args.application.split(":")
        if len(app_parts) != 2:
            parser.error(
                "Application callable must be module name, colon, and callable name."
            )
        app_module = importlib.import_module(app_parts[0])
        app_callable = None
        for part in app_parts[1].split("."):
            app_callable = getattr(
                app_callable if app_callable is not None else app_module, part
            )
        assert app_callable is not None

        # Run the server.
        start_stop_listener = make_start_stop_listener(args.systemd)
        container = Container(app_callable, args.base_uri)
        adapter.run(
            args.tcp, args.unix_socket, extra_sockets, container, start_stop_listener
        )
    finally:
        logging.shutdown()
