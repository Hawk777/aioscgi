"""
An ASGI server that speaks SCGI.

aioscgi is designed as a set of core protocol handlers which are asynchronous but
agnostic to the choice of asynchronous framework in use, plus a set of I/O adapters
which connect the protocol handlers to a specific I/O framework (such as asyncio).

I/O adapters are setuptools entry points in the aioscgi.io group, allowing
other packages to add their own. An adapter must expose a function named “run”. See the
asyncio module for its signature.

Please see the individual modules for more details.
"""
