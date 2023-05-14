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
