"""Per-connection bookkeeping"""

from datetime import datetime


class ConnectionInfo:
    """Class to store connection information"""

    def __init__(self, src_ip: str, dst_domain: str, method: str):

        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0

    def access_log_line(self) -> str:
        """Line written to the access log when the connection is closed"""

        return (
            f"{self.start_time} {self.src_ip} {self.method} "
            f"{self.dst_domain} {self.traffic_in} {self.traffic_out}"
        )
