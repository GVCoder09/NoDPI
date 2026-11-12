"""Ways of sending the fragmented ClientHello to the server"""

import asyncio
import socket

from typing import List

DISORDER_TTL = 1
DISORDER_DELAY = 0.01


async def send_plain(writer: asyncio.StreamWriter, parts: List[bytes]) -> None:
    """Send all parts at once"""

    writer.write(b"".join(parts))
    await writer.drain()


async def send_disorder(
    writer: asyncio.StreamWriter, first: bytes, rest: bytes
) -> None:
    """
    Send the first segment with a low TTL so it is dropped before DPI,
    then the rest normally. The kernel retransmits the first segment
    later with the restored TTL, so DPI sees the stream out of order.
    """

    sock = writer.get_extra_info("socket")
    if sock.family == socket.AF_INET6:
        level = socket.IPPROTO_IPV6
        option = getattr(socket, "IPV6_UNICAST_HOPS", 16)
    else:
        level, option = socket.IPPROTO_IP, socket.IP_TTL

    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    default_ttl = sock.getsockopt(level, option)
    sock.setsockopt(level, option, DISORDER_TTL)
    try:
        writer.write(first)
        await writer.drain()
        await asyncio.sleep(DISORDER_DELAY)
    finally:
        sock.setsockopt(level, option, default_ttl)

    writer.write(rest)
    await writer.drain()


async def send_fragments(
    writer: asyncio.StreamWriter, parts: List[bytes], disordering: bool
) -> None:
    """Send fragmented ClientHello using the configured method"""

    if disordering and len(parts) > 2:
        await send_disorder(writer, parts[0] + parts[1], b"".join(parts[2:]))
    else:
        await send_plain(writer, parts)
