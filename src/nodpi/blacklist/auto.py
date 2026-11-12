"""Blacklist that detects blocked domains automatically"""

import asyncio
import ssl
from typing import List

from nodpi.config import ProxyConfig
from nodpi.dns import Resolver
from nodpi.interfaces import IBlacklistManager
from nodpi.net import connect_any

CHECK_TIMEOUT = 4
HTTPS_PORT = 443


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains"""

    def __init__(self, config: ProxyConfig, resolver: Resolver):

        self.blacklist_file = config.blacklist_file
        self.out_host = config.out_host
        self.resolver = resolver
        self.blocked: List[str] = []
        self.whitelist: List[str] = []
        self._ssl = ssl.create_default_context()
        self._ssl.check_hostname = False
        self._ssl.verify_mode = ssl.CERT_NONE

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        return domain in self.blocked

    async def check_domain(self, domain: bytes) -> None:
        """Mark the domain as blocked if TCP connects but the TLS handshake times out"""

        name = domain.decode()
        if name in self.blocked or name in self.whitelist:
            return

        try:
            addresses = await self.resolver.resolve(name)
            sock = await asyncio.wait_for(
                connect_any(addresses, HTTPS_PORT, self.out_host), CHECK_TIMEOUT
            )
        except Exception:
            return

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=self._ssl, server_hostname=name),
                CHECK_TIMEOUT,
            )
        except asyncio.TimeoutError:
            sock.close()
            self.blocked.append(name)
            with open(self.blacklist_file, "a", encoding="utf-8") as f:
                f.write(name + "\n")
            return
        except Exception:
            sock.close()
            return

        self.whitelist.append(name)
        writer.close()

    def describe(self) -> List[str]:
        return ["Auto-blacklist is enabled"]
