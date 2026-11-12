"""Hosts that repeatedly gave no reply to any ClientHello attempt"""

import time
from typing import Callable, Dict


class DeadHosts:
    """Remembers hosts that failed several races in a row and skips them for a while"""

    def __init__(
        self,
        ttl: float = 300,
        failures_to_mark: int = 2,
        network_alive_window: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ):

        self.ttl = ttl
        self.failures_to_mark = failures_to_mark
        self.network_alive_window = network_alive_window
        self.clock = clock
        self._failures: Dict[str, int] = {}
        self._dead_until: Dict[str, float] = {}
        self._last_success = float("-inf")

    def is_dead(self, host: str) -> bool:
        """True while the host is marked as not answering"""

        until = self._dead_until.get(host)
        if until is None:
            return False
        if self.clock() >= until:
            del self._dead_until[host]
            return False
        return True

    def record_success(self, host: str) -> None:
        """The host answered: forget its failures"""

        self._failures.pop(host, None)
        self._dead_until.pop(host, None)
        self._last_success = self.clock()

    def record_failure(self, host: str) -> bool:
        """Count a failed race; True if the host has just been marked as dead"""

        count = self._failures.get(host, 0) + 1
        now = self.clock()
        network_alive = now - self._last_success <= self.network_alive_window
        if count >= self.failures_to_mark and network_alive:
            self._failures.pop(host, None)
            self._dead_until[host] = now + self.ttl
            return True
        self._failures[host] = count
        return False
