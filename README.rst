What is aioscgi?
================

aioscgi is a container implementing the Asynchronous Server Gateway Interface
(ASGI_) to serve up asynchronous Web applications via the Simple Common Gateway
Interface protocol.


What is SCGI?
=============

SCGI is a protocol used for communication between HTTP servers and Web
applications. Compared to CGI, SCGI is more efficient because it does not fork
and execute a separate instance of the application for every request; instead,
the application is launched ahead of time and receives multiple requests
(either sequentially or concurrently) via socket connections. Compared to
FastCGI, SCGI is a much simpler protocol as it uses a separate socket
connection for each request, rather than including framing within a single
connection to multiplex requests (a feature which is rarely used in FastCGI
anyway due to the lack of per-request flow control).

See the Wikipedia_ and Python_ SCGI pages for more information.


How do I install it?
====================

aioscgi’s releases are published on PyPI for installation through pip. You can
run ``pip install aioscgi``.

For development, the source is available at GitLab_ and GitHub_.


How do I use it?
================

aioscgi installs an ``aioscgi`` executable. If your ASGI application callable
is named ``myapp`` and is in a file called ``mypackage/mymodule.py``, you might
run ``aioscgi --unix-socket /path/to/socket mypackage.mymodule:myapp``. For
full details on available options, run ``aioscgi --help``.


.. _ASGI: https://asgi.readthedocs.io/
.. _Wikipedia: https://en.wikipedia.org/wiki/Simple_Common_Gateway_Interface
.. _Python: http://www.python.ca/scgi/
.. _GitLab: https://gitlab.com/Hawk777/aioscgi
.. _GitHub: https://github.com/Hawk777/aioscgi
