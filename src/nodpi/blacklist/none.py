"""Mode without a blacklist: every domain is subject to unblocking"""

from typing import List

from nodpi.interfaces import IBlacklistManager


class NoBlacklistManager(IBlacklistManager):
    """Blacklist manager that treats every domain as blocked"""

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        return True

    async def check_domain(self, domain: bytes) -> None:
        """Not used in no-blacklist mode"""

    def describe(self) -> List[str]:
        return ["Blacklist is disabled. All domains will be subject to unblocking."]
