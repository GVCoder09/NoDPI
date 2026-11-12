"""Blacklist loaded from a text file"""

import os
from typing import List

from nodpi.config import ProxyConfig
from nodpi.interfaces import IBlacklistManager


class FileBlacklistManager(IBlacklistManager):
    """Blacklist manager that uses file-based blacklist"""

    def __init__(self, config: ProxyConfig):

        self.config = config
        self.blacklist_file = self.config.blacklist_file
        self.blocked: List[str] = []
        self.load_blacklist()

    def load_blacklist(self) -> None:
        """Load blacklist from file"""

        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")

        with open(self.blacklist_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line.strip()) < 2 or line.strip()[0] == "#":
                    continue
                self.blocked.append(line.strip().lower().replace("www.", ""))

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        domain = domain.replace("www.", "")

        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True

        if domain in self.blocked:
            return True

        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in self.blocked:
                return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Not used in file-based mode"""

    def describe(self) -> List[str]:
        return [
            f"Blacklist contains {len(self.blocked)} domains",
            f"Path to blacklist: '{os.path.normpath(self.blacklist_file)}'",
        ]
