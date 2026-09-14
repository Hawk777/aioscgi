# What is aioscgi?

aioscgi is a container implementing the Asynchronous Server Gateway Interface
[ASGI](https://asgi.readthedocs.io/) to serve up asynchronous Web applications
via the Simple Common Gateway Interface protocol. aioscgi supports listening on
TCP or UNIX-domain sockets, as well as using sockets passed in via the systemd
socket-passing protocol. In a systemd environment, when running as a service,
it supports `Type=notify`.


# What is SCGI?

SCGI is a protocol used for communication between HTTP servers and Web
applications. Compared to CGI, SCGI is more efficient because it does not fork
and execute a separate instance of the application for every request; instead,
the application is launched ahead of time and receives multiple requests
(either sequentially or concurrently) via socket connections. Compared to
FastCGI, SCGI is a much simpler protocol as it uses a separate socket
connection for each request, rather than including framing within a single
connection to multiplex requests (a feature which is rarely used in FastCGI
anyway due to the lack of per-request flow control).

See the
[Wikipedia](https://en.wikipedia.org/wiki/Simple_Common_Gateway_Interface) and
[Python](http://www.python.ca/scgi/) SCGI pages for more information.


# How do I install it?

aioscgi’s releases are published on PyPI for installation through pip. You can
run `pip install aioscgi`.

For development, the source is available at
[GitLab](https://gitlab.com/Hawk777/aioscgi) and
[GitHub](https://github.com/Hawk777/aioscgi).


# How do I use it?

aioscgi installs an `aioscgi` executable. If your ASGI application callable is
named `myapp` and is in a file called `mypackage/mymodule.py`, you might run
`aioscgi --unix-socket /path/to/socket mypackage.mymodule:myapp`. For full
details on available options, run `aioscgi --help`.


# What ASGI protocols does it implement?

aioscgi implements the `http` and `lifespan` protocols.


# What ASGI extensions does it implement?

## environ

aioscgi implements a non-standard extension in the `http` scope named
`environ`. `scope["extensions"]["environ"]` is a dictionary with `str` keys and
`bytes` values containing the entire CGI environment, exactly as sent by the
SCGI client. This can be used to extract values that the ASGI specification
does not provide a home for.

## http.response.pathsend

aioscgi implements [the HTTP Path Send
extension](https://asgi.readthedocs.io/en/stable/extensions.html#path-send)
using the `X-Sendfile` header. Because it is not possible to automatically
detect whether a given HTTP server understands that header or not, support is
disabled by default and must be enabled with a command-line option.


# How does it connect to the rest of my system?

## Listening

aioscgi can listen on one or more TCP or UNIX-domain sockets. It can also use listening
TCP or UNIX-domain sockets given to it via systemd socket passing. It can listen on
multiple sockets, including sockets of different domains and/or a mixture of created
sockets and passed sockets, at the same time.

## Startup notification

aioscgi supports the systemd service status notification protocol and therefore can be
invoked as a service with `Type=notify`. It reports startup complete (`READY=1`) after
the application’s lifespan protocol startup process (if any) is complete and any
listening sockets created by aioscgi itself have been created. It reports shutdown in
progress (`STOPPING=1`) as soon as it is instructed to begin shutting down.

## Control

On a UNIX system, aioscgi handles three signals:
* When aioscgi receives `SIGINT`, it immediately stops accepting new connections on any
  listening socket. It then waits for all existing tasks that were spawned to handle
  client connections to end naturally before performing lifespan protocol shutdown and
  terminating. Further `SIGINT`s after the first are ignored.
* When aioscgi receives `SIGTERM`, it behaves exactly the same as `SIGINT`.
* When aioscgi receives `SIGQUIT`, it does everything described for `SIGINT`, except
  that it also raises a cancellation exception in every task that was spawned to handle
  a client connection with the intention of making them stop faster. `SIGQUIT` can also
  be sent after `SIGINT` or `SIGTERM`, in which case the cancellation exception is
  raised in any still-running client-connection-handling tasks. Further `SIGQUIT`s after
  the first are ignored. Even though `SIGQUIT` cancels client-connection-handling tasks,
  the application’s lifespan protocol task (if any) is not cancelled and the normal
  lifespan shutdown process still occurs.
