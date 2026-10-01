"""Helper functions used by the HTTP and WebSocket protocols."""

import http

import sioscgi.response

from .types import EventOrScope


def _calc_status(status: int) -> str:
    """
    Generate the HTTP status string.

    :param status: The status code.
    :returns: The status line including the reason phrase.
    """
    try:
        phrase = http.HTTPStatus(status).phrase
    except ValueError:
        phrase = "Unknown Status"
    return f"{status} {phrase}"


def encode_response_start(event: EventOrScope) -> sioscgi.response.Headers:
    """
    Convert a response-start event into a Headers event.

    :param event: The event to convert.
    :return: The converted event.
    """
    status_code = event["status"]
    assert isinstance(status_code, int)
    headers = event["headers"]
    assert isinstance(headers, list)
    string_headers = (
        (k.decode("ISO-8859-1"), v.decode("ISO-8859-1")) for k, v in headers
    )
    # The ASGI specification says the application is allowed to send
    # Transfer-Encoding and the container is required to ignore it.
    filtered_headers = [
        (k, v) for k, v in string_headers if k.lower() != "transfer-encoding"
    ]
    return sioscgi.response.Headers(_calc_status(status_code), filtered_headers)
