"""Name resolution: DoH server chain with system DNS as the last resort"""

import asyncio
import socket
import time
from typing import Callable, Dict, List, Optional, Tuple

from nodpi.dns.doh import DohServer
from nodpi.dns.message import (
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_AAAA,
    build_query,
    parse_response,
)
from nodpi.net import Address, is_ip

QUERY_TIMEOUT = 2.5
MIN_TTL = 30
MAX_TTL = 3600
NEGATIVE_TTL = 30
FAILURES_TO_SKIP = 3
SKIP_SERVER_FOR = 300

LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".lan",
    ".home",
    ".home.arpa",
    ".corp",
    ".internal",
    ".intranet",
    ".private",
)


def builtin_servers(local_host: Optional[str] = None) -> List[DohServer]:
    """Google and Cloudflare, both reached by IP without SNI"""

    return [
        DohServer("https://8.8.8.8/dns-query", "Google", ["8.8.8.8", "8.8.4.4"], local_host),
        DohServer("https://1.1.1.1/dns-query", "Cloudflare", ["1.1.1.1", "1.0.0.1"], local_host),
    ]


def is_local_name(host: str) -> bool:
    """Names that must go to the system resolver: loopback, single-label, internal zones"""

    name = host.rstrip(".").lower()
    return name == "localhost" or "." not in name or name.endswith(LOCAL_SUFFIXES)


class Resolver:
    """Resolve host names via the DoH chain, falling back to the system resolver"""

    def __init__(
        self,
        servers: List[DohServer],
        use_doh: bool = True,
        on_error: Optional[Callable[[str], None]] = None,
    ):

        self.servers = servers
        self.use_doh = use_doh
        self.on_error = on_error
        self._cache: Dict[str, Tuple[float, List[Address]]] = {}
        self._inflight: Dict[str, asyncio.Future] = {}
        self._failures: Dict[str, int] = {}
        self._skip_until: Dict[str, float] = {}

    def describe(self) -> str:
        """Human readable resolver chain for the startup banner"""

        if not self.use_doh:
            return "DNS over HTTPS is disabled, system DNS is used"
        chain = ", then ".join([s.name for s in self.servers] + ["system DNS"])
        return f"DNS over HTTPS is enabled: {chain}"

    async def resolve(self, host: str) -> List[Address]:
        """Return (family, ip) pairs for a host; raises socket.gaierror if it does not exist"""

        host = host.strip("[]")
        if is_ip(host):
            return [(socket.AF_INET6 if ":" in host else socket.AF_INET, host)]
        if not self.use_doh or is_local_name(host):
            return await self._system(host)

        key = host.lower().rstrip(".")
        cached = self._cache.get(key)
        if cached and cached[0] > time.monotonic():
            if not cached[1]:
                raise socket.gaierror(socket.EAI_NONAME, f"{host} not found")
            return cached[1]

        future = self._inflight.get(key)
        if future is None:
            future = asyncio.ensure_future(self._resolve_uncached(key))
            self._inflight[key] = future
            future.add_done_callback(lambda _: self._inflight.pop(key, None))
        return await asyncio.shield(future)

    async def _resolve_uncached(self, host: str, skip: Optional[DohServer] = None) -> List[Address]:
        for server in self.servers:
            if server is skip or self._skipped(server):
                continue
            try:
                answer = await self._query_server(server, host)
            except Exception as e:
                self._record_failure(server, e)
                continue
            self._failures.pop(server.url, None)
            addresses, ttl = answer
            expiry = time.monotonic() + (
                max(MIN_TTL, min(ttl, MAX_TTL)) if addresses else NEGATIVE_TTL
            )
            if skip is None:
                self._cache[host] = (expiry, addresses)
            if not addresses:
                raise socket.gaierror(socket.EAI_NONAME, f"{host} not found")
            return addresses
        return await self._system(host)

    async def _query_server(self, server: DohServer, host: str) -> Tuple[List[Address], int]:
        async def bootstrap(name: str) -> List[Address]:
            return await self._resolve_uncached(name.lower(), skip=server)

        async def one(qtype: int) -> Tuple[int, List[str], int]:
            raw = await asyncio.wait_for(
                server.query(build_query(host, qtype), bootstrap), QUERY_TIMEOUT
            )
            return parse_response(raw, qtype)

        results = await asyncio.gather(one(TYPE_A), one(TYPE_AAAA), return_exceptions=True)
        answers = [r for r in results if not isinstance(r, BaseException)]
        if not answers:
            raise results[0]
        if all(r[0] not in (RCODE_NOERROR, RCODE_NXDOMAIN) for r in answers):
            raise OSError(f"DNS error code {answers[0][0]}")

        addresses: List[Address] = []
        ttls: List[int] = []
        for qtype, result in zip((TYPE_A, TYPE_AAAA), results):
            if isinstance(result, BaseException) or result[0] != RCODE_NOERROR:
                continue
            family = socket.AF_INET if qtype == TYPE_A else socket.AF_INET6
            addresses.extend((family, ip) for ip in result[1])
            if result[1]:
                ttls.append(result[2])
        return addresses, min(ttls) if ttls else 0

    async def _system(self, host: str) -> List[Address]:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        seen: List[Address] = []
        for family, _, _, _, sockaddr in infos:
            address = (family, sockaddr[0])
            if family in (socket.AF_INET, socket.AF_INET6) and address not in seen:
                seen.append(address)
        return seen

    def _skipped(self, server: DohServer) -> bool:
        until = self._skip_until.get(server.url)
        if until is None:
            return False
        if time.monotonic() >= until:
            del self._skip_until[server.url]
            return False
        return True

    def _record_failure(self, server: DohServer, error: Exception) -> None:
        count = self._failures.get(server.url, 0) + 1
        if count >= FAILURES_TO_SKIP:
            self._failures.pop(server.url, None)
            self._skip_until[server.url] = time.monotonic() + SKIP_SERVER_FOR
            if self.on_error:
                reason = f"{type(error).__name__}: {error}".rstrip(": ")
                self.on_error(
                    f"DoH server {server.url} failed {count} times in a row "
                    f"({reason}), skipping it for {SKIP_SERVER_FOR} s"
                )
        else:
            self._failures[server.url] = count
