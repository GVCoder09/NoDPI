"""Connecting to a host given a list of resolved addresses (RFC 8305 style)"""

import asyncio
import ipaddress
import socket
from typing import List, Optional, Tuple

Address = Tuple[int, str]

HAPPY_EYEBALLS_DELAY = 0.25


def is_ip(host: str) -> bool:
    """True for an IPv4 or IPv6 literal"""

    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def interleave(addresses: List[Address]) -> List[Address]:
    """Alternate address families, keeping the order within each family"""

    if not addresses:
        return []
    first = addresses[0][0]
    a = [x for x in addresses if x[0] == first]
    b = [x for x in addresses if x[0] != first]
    out: List[Address] = []
    for i in range(max(len(a), len(b))):
        out.extend(a[i : i + 1])
        out.extend(b[i : i + 1])
    return out


async def _connect_one(address: Address, port: int, local_host: Optional[str]) -> socket.socket:
    family, ip = address
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        if local_host:
            sock.bind((local_host, 0))
        await asyncio.get_running_loop().sock_connect(sock, (ip, port))
        return sock
    except BaseException:
        sock.close()
        raise


async def connect_any(
    addresses: List[Address],
    port: int,
    local_host: Optional[str] = None,
    delay: float = HAPPY_EYEBALLS_DELAY,
) -> socket.socket:
    """Connect to the first address that answers, starting attempts ``delay`` apart"""

    if local_host:
        local_family = socket.AF_INET6 if ":" in local_host else socket.AF_INET
        addresses = [a for a in addresses if a[0] == local_family]
    candidates = interleave(addresses)
    if not candidates:
        raise OSError(f"no usable address to connect to port {port}")

    tasks: List[asyncio.Task] = []
    errors: List[BaseException] = []
    winner: Optional[socket.socket] = None
    try:
        for address in candidates:
            tasks.append(asyncio.ensure_future(_connect_one(address, port, local_host)))
            winner = await _wait_first(tasks, delay, errors)
            if winner:
                return winner
        while any(not t.done() for t in tasks):
            winner = await _wait_first(tasks, None, errors)
            if winner:
                return winner
        raise errors[-1] if errors else OSError("connection failed")
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for t in tasks:
            succeeded = t.done() and not t.cancelled() and t.exception() is None
            if succeeded and t.result() is not winner:
                t.result().close()


async def _wait_first(
    tasks: List[asyncio.Task], timeout: Optional[float], errors: List[BaseException]
) -> Optional[socket.socket]:
    pending = {t for t in tasks if not t.done()}
    if pending:
        await asyncio.wait(pending, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        if t.done() and not t.cancelled():
            exc = t.exception()
            if exc is None:
                return t.result()
            if exc not in errors:
                errors.append(exc)
    return None
