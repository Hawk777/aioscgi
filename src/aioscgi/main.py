"""The application entry point."""

import argparse
import importlib
import importlib.metadata
import json
import logging
import logging.config
import pathlib
import sys

from . import core


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
            type=pathlib.Path,
            help="the UNIX socket path to listen on",
        )
        parser.add_argument(
            "--tcp-port", "-p", type=int, help="the TCP port to listen on"
        )
        parser.add_argument(
            "--tcp-host",
            action="append",
            help="the IP address(es) or hostname(s) to listen on (for TCP) (default: "
            "all interfaces)",
        )
        parser.add_argument(
            "application", help="the dotted.module.name:callable of the application"
        )
        args = parser.parse_args()
        if sum(i is not None for i in (args.unix_socket, args.tcp_port)) != 1:
            parser.error(
                "Exactly one of --unix-socket and --tcp-port must be supplied."
            )

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
        if len(app_parts) != 2:  # noqa: PLR2004
            parser.error(
                "Application callable must be module name, colon, and callable name."
            )
        app_module = importlib.import_module(app_parts[0])
        app_callable = app_module
        for part in app_parts[1].split("."):
            app_callable = getattr(app_callable, part)

        # Run the server.
        container = core.Container(args.base_uri)
        if args.tcp_port:
            hosts = args.tcp_host
            if not hosts:
                hosts = None
            adapter.run_tcp(app_callable, hosts, args.tcp_port, container)
        else:
            adapter.run_unix(app_callable, args.unix_socket, container)
    finally:
        logging.shutdown()
