Changes in 2.3.1
================

Very minor code cleanup was performed. Compatibility with Python 3.13 was added.

Changes in 2.3.0
================

Breaking changes
----------------

This version requires Python 3.11 or higher due to the use of ``typing.Self``.

In the accordance with commit c3d70c3e7a1b7a73d2688c574d47766ebfa100d1 on the
``asgiref`` repository, HTTP response headers are sent immediately; it is no
longer possible for the application to replace its headers once they have been
sent the first time.

aioscgi now implements version 2.4 of the HTTP protocol.

The ``--tcp-host`` and ``--tcp-port`` options have been combined into a single
``--tcp`` option (see New Features for more details).

The API between the aioscgi’s core logic and the I/O adapter has been
completely refactored. This does not affect applications but requires any
third-party I/O adapters to be updated.

New features
------------

aioscgi can now listen on more than one endpoint at the same time, whether
multiple UNIX-domain sockets, multiple TCP sockets, or a combination thereof.
To accommodate this, the ``--unix-socket`` option can be passed more than once.
The ``--tcp-host`` and ``--tcp-port`` options have been combined into a single
``--tcp`` option (allowing the choice of host to be made on a per-port basis)
which can also be specified more than once, including in combination with
``--unix-socket``.

aioscgi now supports integration with systemd, enabled by passing the
``--systemd`` option on the command line. This integration takes two forms:
1. If systemd provides a notification socket, it will be used to report service
   startup and shutdown progress. This allows aioscgi to be run in a service
   unit of ``Type=notify``. The service will be considered “started” once the
   lifespan protocol startup is complete and any listening sockets have been
   created and bound. The service will be considered “stopping” as soon as it
   begins the shutdown process, prior to completion of any in-progress requests
   and lifespan protocol shutdown.
2. Listening sockets can be passed from systemd instead of, or in addition to,
   being specified with ``--tcp`` and ``--unix-socket``. This is done by
   creating a socket unit with the same name as the service unit, or by setting
   the ``Service=`` option in the socket unit. The ``NonBlocking=true`` option
   must be set in the service unit. This allows sockets to be bound on
   endpoints that aioscgi itself does not have permission to bind; for example,
   TCP ports less than 1024 or UNIX-domain sockets in directories without write
   access. This mechanism is also compatible with socket activation, allowing
   aioscgi’s startup to be delayed until the first connection is received.

Bug fixes
---------

According to the ASGI specification, an application is allowed to provide a
``Transfer-Encoding`` HTTP response header, which must be ignored. aioscgi
previously, incorrectly, passed it to the SCGI client; it now deletes it.

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
