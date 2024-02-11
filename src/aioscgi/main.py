"""The application entry point."""

import argparse
import importlib
import importlib.metadata
import json
import logging
import logging.config
import pathlib
import sys
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
            "application", help="the dotted.module.name:callable of the application"
        )
        args = parser.parse_args()
        if not any(i for i in (args.unix_socket, args.tcp)):
            parser.error("At least one of --unix-socket or --tcp must be supplied.")

        # Set up logging.
        if args.logging is not None:
            with args.logging.open("rb") as logging_config_file:
                cfg = json.load(logging_config_file)
            logging.config.dictConfig(cfg)
        else:
            logging.basicConfig(level=logging.INFO)

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
        start_stop_listener = NullaryListener()
        container = Container(app_callable, args.base_uri)
        adapter.run(args.tcp, args.unix_socket, container, start_stop_listener)
    finally:
        logging.shutdown()
