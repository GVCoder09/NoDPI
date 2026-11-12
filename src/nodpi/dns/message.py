"""Minimal DNS wire format (RFC 1035): A/AAAA queries and answers"""

import socket
import struct
from typing import List, Tuple

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

_FAMILY = {TYPE_A: socket.AF_INET, TYPE_AAAA: socket.AF_INET6}


class DnsFormatError(Exception):
    """Malformed DNS message"""


def encode_name(name: str) -> bytes:
    """Domain name to DNS label format"""

    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid domain name: {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int) -> bytes:
    """Recursive query for one name and type, id 0 as recommended for DoH"""

    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        if pos >= len(data):
            raise DnsFormatError("name runs past the end")
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length


def parse_response(data: bytes, qtype: int) -> Tuple[int, List[str], int]:
    """Return (rcode, addresses of qtype, minimal TTL) from a response"""

    if len(data) < 12:
        raise DnsFormatError("message too short")
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if not flags & 0x8000:
        raise DnsFormatError("not a response")
    rcode = flags & 0x000F

    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(data, pos) + 4

    addresses: List[str] = []
    ttls: List[int] = []
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        if pos + 10 > len(data):
            raise DnsFormatError("record header runs past the end")
        rtype, _, ttl, rdlength = struct.unpack(">HHIH", data[pos : pos + 10])
        pos += 10
        rdata = data[pos : pos + rdlength]
        if len(rdata) != rdlength:
            raise DnsFormatError("record data runs past the end")
        pos += rdlength
        if rtype == qtype and qtype in _FAMILY:
            addresses.append(socket.inet_ntop(_FAMILY[qtype], rdata))
            ttls.append(ttl)

    return rcode, addresses, min(ttls) if ttls else 0
