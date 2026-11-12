"""Ways of sending the fragmented ClientHello to the server"""

import asyncio
import socket
from typing import List

DISORDER_TTL = 1
DISORDER_DELAY = 0.01
OOB_BYTE = b"\x00"
OOB_DELAY = 0.005
FLUSH_TIMEOUT = 2


async def send_plain(writer: asyncio.StreamWriter, parts: List[bytes]) -> None:
    """Send all parts at once"""

    writer.write(b"".join(parts))
    await writer.drain()


async def send_disorder(writer: asyncio.StreamWriter, first: bytes, rest: bytes) -> None:
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


async def _wait_flushed(writer: asyncio.StreamWriter) -> None:
    deadline = asyncio.get_running_loop().time() + FLUSH_TIMEOUT
    while writer.transport.get_write_buffer_size() > 0:
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError("write buffer was not flushed")
        await asyncio.sleep(0.001)


async def send_oob(writer: asyncio.StreamWriter, parts: List[bytes]) -> None:
    """Send the parts with one urgent (MSG_OOB) byte in the middle, ignored by the server"""

    mid = len(parts) // 2
    tsock = writer.get_extra_info("socket")
    tsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    writer.write(b"".join(parts[:mid]))
    await writer.drain()
    await _wait_flushed(writer)

    raw = socket.socket(tsock.family, tsock.type, tsock.proto, fileno=tsock.fileno())
    try:
        raw.send(OOB_BYTE, socket.MSG_OOB)
    finally:
        raw.detach()
    await asyncio.sleep(OOB_DELAY)

    writer.write(b"".join(parts[mid:]))
    await writer.drain()


async def send_with(writer: asyncio.StreamWriter, parts: List[bytes], method: str) -> None:
    """Send fragmented ClientHello with the given method: plain, disorder or oob"""

    if method == "disorder" and len(parts) > 2:
        await send_disorder(writer, parts[0] + parts[1], b"".join(parts[2:]))
    elif method == "oob" and len(parts) > 2:
        await send_oob(writer, parts)
    else:
        await send_plain(writer, parts)


async def send_fragments(
    writer: asyncio.StreamWriter, parts: List[bytes], disordering: bool
) -> None:
    """Send fragmented ClientHello using the configured method"""

    await send_with(writer, parts, "disorder" if disordering else "plain")
