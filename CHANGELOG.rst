Changes in 2.2.0
================

Breaking changes
----------------

In the HTTP protocol, the calculation of ``scope["path"]`` has been fixed. It
used to be incorrectly calculated as equivalent to CGI’s ``PATH_INFO``. In
accordance with a recent clarification of the ASGI specification, it is now
calculated as ``PATH_INFO`` prefixed with ``scope["root_path"]``.

New features
------------

The HTTP protocol now claims to support specification version 2.3, up from 2.1;
the changes between those versions do not affect aioscgi.

The optional “lifespan state” feature (the ``scope["state"]`` dictionary) is
now implemented.

Bug fixes
---------

The lifespan protocol now claims to support specification version 2.0, up from
1.0; aioscgi actually always supported version 2.0’s ``startup.failed`` and
``shutdown.failed`` events, so already implemented 2.0 semantics.


Changes in 2.1.0
================

CI configuration was updated. Very minor code cleanup was performed. This
version requires Python 3.10 or higher due to migrating from pkg_resources to
importlib.metadata for entry points.


Changes in 2.0.3
================

The build system is PEP 517 compliant.


Changes in 2.0.2
================

Python 3.10 is now supported.


Changes in 2.0.1
================

Python 3.9 is now supported.


Changes in 2.0.0
================

The ``scope["extensions"]["environ"]`` dictionary now maps from ``str`` to
``bytes`` rather than from ``str`` to ``str``. This is because HTTP header
values do not have any standards-defined character encoding; therefore, it must
be left up to each application to decode each header as it sees fit, if it
intends to use the header value as textual data.
