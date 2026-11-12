"""Abstract interfaces shared between the proxy components"""

import asyncio
from abc import ABC, abstractmethod
from typing import List


class IBlacklistManager(ABC):
    """Interface for blacklist management"""

    @abstractmethod
    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

    @abstractmethod
    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

    @abstractmethod
    def describe(self) -> List[str]:
        """Human readable lines describing the mode, for the startup banner"""


class ILogger(ABC):
    """Interface for logging"""

    @abstractmethod
    def log_access(self, message: str) -> None:
        """Log access message"""

    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""

    @abstractmethod
    def info(self, *args, **kwargs) -> None:
        """Print info message if not quiet"""

    @abstractmethod
    def error(self, *args, **kwargs) -> None:
        """Print error message if not quiet"""


class IStatistics(ABC):
    """Interface for statistics tracking"""

    @abstractmethod
    def increment_total_connections(self) -> None:
        """Increment total connections counter"""

    @abstractmethod
    def increment_allowed_connections(self) -> None:
        """Increment allowed connections counter"""

    @abstractmethod
    def increment_blocked_connections(self) -> None:
        """Increment blocked connections counter"""

    @abstractmethod
    def increment_error_connections(self) -> None:
        """Increment error connections counter"""

    @abstractmethod
    def update_traffic(self, incoming: int, outgoing: int) -> None:
        """Update traffic counters"""

    @abstractmethod
    def update_speeds(self) -> None:
        """Update speed calculations"""


class IConnectionHandler(ABC):
    """Interface for connection handling"""

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection"""


class IAutostartManager(ABC):
    """Interface for autostart management"""

    @staticmethod
    @abstractmethod
    def manage_autostart(action: str) -> None:
        """Manage autostart"""
