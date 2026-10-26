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


# How do I configure my HTTP server?

## Apache

I have not figured out how to get Apache to reliably set the split between
`SCRIPT_NAME` and `PATH_INFO` where it’s supposed to be, i.e. at the mount
point of the application. Therefore, passing `--base-uri` to aioscgi is
necessary.

You should almost certainly *not* set `AllowEncodedSlashes NoDecode` when using
aioscgi. If you do this, a request like `https://mydomain/myapp/foo%2Fbar` will
put `/foo%2Fbar` in `PATH_INFO`, which will in turn put `/myapp/foo%2Fbar` in
`scope["path"]`, in violation of the ASGI specification which says that
`scope["path"]` must be URL-decoded. Instead, if you need this kind of thing,
set `AllowEncodedSlashes On`. Then `scope["path"]` will be `/myapp/foo/bar`, in
compliance with the ASGI specification, and your application can look at
`scope["raw_path"]` to get `/myapp/foo%2Fbar`.

You can set up
[mod_proxy_scgi](https://httpd.apache.org/docs/2.4/mod/mod_proxy_scgi.html)
to handle requests in two ways, both of which can use either TCP or UNIX-domain
sockets to talk to aioscgi:

```
# Option 1: SetHandler and UNIX-domain sockets
<Proxy "unix:/path/to/socket|scgi://mydomain/myapp/">
</Proxy>
<Location "/myapp/">
    SetHandler "proxy:unix:/path/to/socket|scgi://mydomain/myapp/"
</Location>

# Option 2: SetHandler and TCP sockets
<Proxy "scgi://myscgiserver:1234/myapp/">
</Proxy>
<Location "/myapp/">
    SetHandler "scgi://myscgiserver:1234/myapp/"
</Location>

# Option 3: ProxyPass and UNIX-domain sockets
ProxyPass /myapp/ unix:/path/to/socket|scgi://mydomain/myapp/

# Option 4: ProxyPass and TCP sockets
ProxyPass /myapp/ scgi://myscgiserver:1234/myapp/
```

## Lighttpd

Lighttpd splits `SCRIPT_NAME` and `PATH_INFO` just fine, so there’s no need to
pass `--base-uri` to aioscgi.

```
scgi.server = (
    # The /myapp/ here defines SCRIPT_NAME as well as mapping the SCGI
    # application into the URL space.
    "/myapp/" => ("myapp" => (
        # Include the next line for UNIX-domain sockets.
        "socket" => "/path/to/socket",
        # Include the next two lines for TCP sockets.
        "host" => "myscgiserver",
        "port" => 1234,
        "check-local" => 0,
    )),
)
```
