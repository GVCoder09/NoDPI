"""Connection and traffic counters"""

import time
from typing import Optional, Tuple

from nodpi.interfaces import IStatistics


class Statistics(IStatistics):
    """Statistics tracker for proxy server"""

    def __init__(self):

        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0
        self.errors_connections = 0
        self.traffic_in = 0
        self.traffic_out = 0
        self.last_traffic_in = 0
        self.last_traffic_out = 0
        self.speed_in = 0.0
        self.speed_out = 0.0
        self.average_speed_in: Tuple[float, int] = (0, 1)
        self.average_speed_out: Tuple[float, int] = (0, 1)
        self.last_time: Optional[float] = None

    def increment_total_connections(self) -> None:
        """Increment total connections counter"""
        self.total_connections += 1

    def increment_allowed_connections(self) -> None:
        """Increment allowed connections counter"""
        self.allowed_connections += 1

    def increment_blocked_connections(self) -> None:
        """Increment blocked connections counter"""
        self.blocked_connections += 1

    def increment_error_connections(self) -> None:
        """Increment error connections counter"""
        self.errors_connections += 1

    def update_traffic(self, incoming: int, outgoing: int) -> None:
        """Update traffic counters"""

        self.traffic_in += incoming
        self.traffic_out += outgoing

    def update_speeds(self) -> None:
        """Update speed calculations"""

        current_time = time.time()

        if self.last_time is not None:
            time_diff = current_time - self.last_time
            if time_diff > 0:
                self.speed_in = (self.traffic_in - self.last_traffic_in) * 8 / time_diff
                self.speed_out = (self.traffic_out - self.last_traffic_out) * 8 / time_diff

                if self.speed_in > 0:
                    self.average_speed_in = (
                        self.average_speed_in[0] + self.speed_in,
                        self.average_speed_in[1] + 1,
                    )
                if self.speed_out > 0:
                    self.average_speed_out = (
                        self.average_speed_out[0] + self.speed_out,
                        self.average_speed_out[1] + 1,
                    )

        self.last_traffic_in = self.traffic_in
        self.last_traffic_out = self.traffic_out
        self.last_time = current_time

    @property
    def average_in(self) -> float:
        """Average download speed, bit/s"""

        total, count = self.average_speed_in
        return total / count if count > 0 else 0

    @property
    def average_out(self) -> float:
        """Average upload speed, bit/s"""

        total, count = self.average_speed_out
        return total / count if count > 0 else 0
