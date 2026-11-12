"""Blacklist that detects blocked domains automatically"""

import ssl

from typing import List
from urllib.error import URLError
from urllib.request import Request, urlopen

from nodpi.config import ProxyConfig
from nodpi.interfaces import IBlacklistManager


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains"""

    def __init__(self, config: ProxyConfig):

        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self.whitelist: List[str] = []

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        return domain in self.blocked

    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

        if domain.decode() in self.blocked or domain in self.whitelist:
            return

        try:
            req = Request(
                f"https://{domain.decode()}", headers={"User-Agent": "Mozilla/5.0"}
            )
            context = ssl._create_unverified_context()

            with urlopen(req, timeout=4, context=context):
                self.whitelist.append(domain.decode())
        except URLError as e:
            reason = str(e.reason)
            if "handshake operation timed out" in reason:
                self.blocked.append(domain.decode())
                with open(self.blacklist_file, "a", encoding="utf-8") as f:
                    f.write(domain.decode() + "\n")

    def describe(self) -> List[str]:
        return ["Auto-blacklist is enabled"]
