"""
An ASGI server that speaks SCGI.

aioscgi is designed as a core server (aioscgi.core.run) plus a set of I/O
adapters. The core is designed to be asynchronous but agnostic to the
asynchronous framework in use; thus, an I/O adapter is used to connect the core
to an actual I/O implementation, such as asyncio.

I/O adapters are setuptools entry points in the aioscgi.io group, allowing
other packages to add their own. An adapter must expose functions
run_tcp(app_callable, tcp_hosts, tcp_port) and run_unix(app_callable, path).

Please see the individual modules for more details.
"""
