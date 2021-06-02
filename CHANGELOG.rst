Changes in 2.0.0
================

The ``scope["extensions"]["environ"]`` dictionary now maps from ``str`` to
``bytes`` rather than from ``str`` to ``str``. This is because HTTP header
values do not have any standards-defined character encoding; therefore, it must
be left up to each application to decode each header as it sees fit, if it
intends to use the header value as textual data.
