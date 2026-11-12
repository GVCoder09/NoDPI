"""TLS ClientHello parsing and fragmentation"""

from typing import List, Optional, Tuple

TLS_HANDSHAKE = 0x16
TLS_RECORD_HEADER_LEN = 5
FRAGMENT_RECORD_PREFIX = bytes.fromhex("160304")
SNI_CHUNK_SIZE = 2


def extract_sni_position(data: bytes) -> Optional[Tuple[int, int]]:
    """Find the server name inside a ClientHello record body.

    Returns (start, end) offsets of the host name in ``data`` or None.
    """

    i = 0
    while i < len(data) - 8:
        if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
            ext_len = data[i + 3]
            server_name_list_len = data[i + 5]
            server_name_len = data[i + 8]
            if (
                ext_len - server_name_list_len == 2
                and server_name_list_len - server_name_len == 3
            ):
                sni_start = i + 9
                sni_end = sni_start + server_name_len
                return sni_start, sni_end
        i += 1
    return None


def _record(payload: bytes) -> bytes:
    return FRAGMENT_RECORD_PREFIX + len(payload).to_bytes(2, "big") + payload


def fragment_client_hello(head: bytes, data: bytes) -> List[bytes]:
    """Split a ClientHello into several TLS records around the SNI.

    ``head`` is the original 5-byte record header, ``data`` the record body.
    The result is: [part before SNI], [SNI in 2-byte chunks...], [part after SNI].
    If no SNI is found the original record is returned unchanged.
    """

    sni_pos = extract_sni_position(data)
    if not sni_pos:
        return [head + data]

    part_start = data[: sni_pos[0]]
    sni_data = data[sni_pos[0]: sni_pos[1]]
    part_end = data[sni_pos[1]:]

    parts = [_record(part_start)]
    for i in range(0, len(sni_data), SNI_CHUNK_SIZE):
        parts.append(_record(sni_data[i: i + SNI_CHUNK_SIZE]))
    parts.append(_record(part_end))
    return parts
