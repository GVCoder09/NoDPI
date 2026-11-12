"""HTTP proxy protocol helpers: request parsing, authorization, fixed responses"""

import base64
from typing import Optional, Tuple

CONNECTION_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
INTERNAL_SERVER_ERROR = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
PROXY_AUTH_REQUIRED = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="NoDPI Proxy"\r\n'
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


def parse_http_request(http_data: bytes) -> Tuple[bytes, bytes, int]:
    """Parse HTTP request to extract method, host and port"""

    headers = http_data.split(b"\r\n")
    first_line = headers[0].split(b" ")
    method = first_line[0]
    url = first_line[1]

    if method == b"CONNECT":
        host_port = url.split(b":")
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
    else:
        host_header = next((h for h in headers if h.startswith(b"Host: ")), None)
        if not host_header:
            raise ValueError("Missing Host header")

        host_port = host_header[6:].split(b":")
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 80

    return method, host, port


def check_basic_auth(http_data: bytes, username: Optional[str], password: Optional[str]) -> bool:
    """Check the Proxy-Authorization header against the expected credentials"""

    auth_header = None
    for line in http_data.split(b"\r\n"):
        if line.lower().startswith(b"proxy-authorization:"):
            auth_header = line
            break

    if auth_header is None:
        return False

    parts = auth_header.split(b" ", 2)
    if len(parts) != 3 or parts[1].lower() != b"basic":
        return False

    try:
        decoded = base64.b64decode(parts[2].strip()).decode("utf-8")
        given_username, given_password = decoded.split(":", 1)
    except Exception:
        return False

    return given_username == username and given_password == password
