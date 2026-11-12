"""DNS over HTTPS client (RFC 8484, HTTP/1.1 POST with keep-alive)"""

import asyncio
import contextlib
import socket
import ssl
from typing import Awaitable, Callable, List, Optional, Tuple
from urllib.parse import urlsplit

from nodpi.net import Address, connect_any, is_ip

MAX_IDLE_CONNECTIONS = 4
MAX_RESPONSE_SIZE = 65535

Connection = Tuple[asyncio.StreamReader, asyncio.StreamWriter]
Bootstrap = Callable[[str], Awaitable[List[Address]]]


class DohError(Exception):
    """DoH request failed"""


def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


class DohServer:
    """One DoH resolver reached by IP; a domain in the URL is used as SNI"""

    def __init__(
        self,
        url: str,
        name: Optional[str] = None,
        ips: Optional[List[str]] = None,
        local_host: Optional[str] = None,
    ):

        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"DoH server must be an https:// URL: {url!r}")
        self.url = url
        self.host = parts.hostname
        self.port = parts.port or 443
        self.path = (parts.path or "/dns-query") + (f"?{parts.query}" if parts.query else "")
        self.name = name or self.host
        self.local_host = local_host
        self.by_ip = is_ip(self.host)
        self._ips: Optional[List[str]] = ips or ([self.host] if self.by_ip else None)
        self._idle: List[Connection] = []
        self._ssl = ssl.create_default_context()

    @property
    def sni(self) -> Optional[str]:
        """Server name sent in the ClientHello, None when connecting by IP"""

        return None if self.by_ip else self.host

    async def _addresses(self, bootstrap: Bootstrap) -> List[Address]:
        if self._ips is None:
            resolved = await bootstrap(self.host)
            if not resolved:
                raise DohError(f"cannot resolve DoH server {self.host}")
            self._ips = [ip for _, ip in resolved]
        return [(_family(ip), ip) for ip in self._ips]

    async def _open(self, bootstrap: Bootstrap) -> Connection:
        sock = await connect_any(await self._addresses(bootstrap), self.port, self.local_host)
        server_hostname = self.host if not self.by_ip else sock.getpeername()[0]
        try:
            return await asyncio.open_connection(
                sock=sock, ssl=self._ssl, server_hostname=server_hostname
            )
        except BaseException:
            sock.close()
            raise

    def _request(self, query: bytes) -> bytes:
        host = f"[{self.host}]" if ":" in self.host else self.host
        head = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            f"Content-Length: {len(query)}\r\n"
            "\r\n"
        )
        return head.encode() + query

    async def _exchange(self, conn: Connection, query: bytes) -> Tuple[bytes, bool]:
        reader, writer = conn
        writer.write(self._request(query))
        await writer.drain()

        status = await reader.readline()
        if not status:
            raise DohError("connection closed")
        parts = status.split(b" ", 2)
        if len(parts) < 2 or parts[1] != b"200":
            raise DohError(f"HTTP status {status.strip().decode(errors='replace')}")

        length: Optional[int] = None
        chunked = False
        keep_alive = True
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, value = line.decode("latin-1").partition(":")
            key, value = key.strip().lower(), value.strip().lower()
            if key == "content-length":
                length = int(value)
            elif key == "transfer-encoding" and "chunked" in value:
                chunked = True
            elif key == "connection" and value == "close":
                keep_alive = False

        if chunked:
            body = b""
            while True:
                size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    await reader.readline()
                    break
                body += await reader.readexactly(size)
                await reader.readexactly(2)
                if len(body) > MAX_RESPONSE_SIZE:
                    raise DohError("response too large")
        elif length is not None:
            if length > MAX_RESPONSE_SIZE:
                raise DohError("response too large")
            body = await reader.readexactly(length)
        else:
            body = await reader.read(MAX_RESPONSE_SIZE)
            keep_alive = False
        return body, keep_alive

    async def query(self, query: bytes, bootstrap: Bootstrap) -> bytes:
        """Send one DNS query and return the raw DNS response"""

        reused = bool(self._idle)
        conn = self._idle.pop() if reused else await self._open(bootstrap)
        try:
            body, keep_alive = await self._exchange(conn, query)
        except (OSError, asyncio.IncompleteReadError, DohError):
            _close(conn)
            if not reused:
                raise
            conn = await self._open(bootstrap)
            try:
                body, keep_alive = await self._exchange(conn, query)
            except BaseException:
                _close(conn)
                raise
        except BaseException:
            _close(conn)
            raise

        if keep_alive and len(self._idle) < MAX_IDLE_CONNECTIONS:
            self._idle.append(conn)
        else:
            _close(conn)
        return body


def _close(conn: Connection) -> None:
    with contextlib.suppress(Exception):
        conn[1].close()
