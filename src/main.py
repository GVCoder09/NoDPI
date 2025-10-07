#!/usr/bin/env python3

"""
NoDPI
=====

NoDPI is a utility for bypassing the DPI (Deep Packet Inspection) system
"""

import argparse
import asyncio
import logging
import os
import random
import ssl
import sys
import textwrap
import time
import traceback

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.error import URLError
from urllib.request import urlopen, Request

if sys.platform == "win32":
    import winreg

__version__ = "2.0-dev"

os.system("")


class ConnectionInfo:
    """Class to store connection information"""

    def __init__(self, src_ip: str, dst_domain: str, method: str):

        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0


class ProxyConfig:
    """Configuration container for proxy settings"""

    def __init__(self):

        self.host = "127.0.0.1"
        self.port = 8881
        self.out_host = "127.0.0.1"
        self.blacklist_file = "blacklist.txt"
        self.fragment_method = "random"
        self.domain_matching = "strict"
        self.log_access_file = None
        self.log_error_file = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False


class IBlacklistManager(ABC):
    """Interface for blacklist management"""

    @abstractmethod
    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

    @abstractmethod
    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""


class ILogger(ABC):
    """Interface for logging"""

    @abstractmethod
    def log_access(self, message: str) -> None:
        """Log access message"""

    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""

    @abstractmethod
    def info(self, message: str) -> None:
        """Print info message if not quiet"""

    @abstractmethod
    def error(self, message: str) -> None:
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

    @abstractmethod
    def get_stats_display(self) -> str:
        """Get statistics display string"""


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

        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line.strip()) < 2 or line.strip()[0] == '#':
                    continue
                self.blocked.append(line.strip().lower())

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True

        if domain in self.blocked:
            return True

        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.blocked:
                return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Not used in file-based mode"""


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains"""

    def __init__(self, config: ProxyConfig,):

        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self.whitelist: List[str] = []

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        if domain in self.blocked:
            return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

        if domain in self.blocked or domain in self.whitelist:
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


class NoBlacklistManager(IBlacklistManager):
    """Blacklist manager that doesn't block anything"""

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        return True

    async def check_domain(self, domain: bytes) -> None:
        """Not used in no-blacklist mode"""


class ProxyLogger(ILogger):
    """Logger implementation for proxy server"""

    def __init__(
        self,
        log_access_file: Optional[str],
        log_error_file: Optional[str],
        quiet: bool = False,
    ):

        self.quiet = quiet
        self.logger = logging.getLogger(__name__)
        self.error_counter_callback = None
        self.setup_logging(log_access_file, log_error_file)

    def setup_logging(
        self, log_access_file: Optional[str], log_error_file: Optional[str]
    ) -> None:
        """Setup logging configuration"""

        class ErrorCounterHandler(logging.FileHandler):
            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback

            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.counter_callback()
                super().emit(record)

        if log_error_file:
            error_handler = ErrorCounterHandler(
                self.increment_errors, log_error_file, encoding="utf-8"
            )
            error_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"
                )
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.addFilter(
                lambda record: record.levelno == logging.ERROR)
        else:
            error_handler = logging.NullHandler()

        if log_access_file:
            access_handler = logging.FileHandler(
                log_access_file, encoding="utf-8")
            access_handler.setFormatter(logging.Formatter("%(message)s"))
            access_handler.setLevel(logging.INFO)
            access_handler.addFilter(
                lambda record: record.levelno == logging.INFO)
        else:
            access_handler = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(access_handler)

    def set_error_counter_callback(self, callback):
        """Set callback for error counting"""
        self.error_counter_callback = callback

    def increment_errors(self) -> None:
        """Increment error counter"""

        if self.error_counter_callback:
            self.error_counter_callback()

    def log_access(self, message: str) -> None:
        """Log access message"""
        self.logger.info(message)

    def log_error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)

    def info(self, *args, **kwargs) -> None:
        """Print info message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)

    def error(self, *args, **kwargs) -> None:
        """Print error message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)


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
        self.speed_in = 0
        self.speed_out = 0
        self.average_speed_in = (0, 1)
        self.average_speed_out = (0, 1)
        self.last_time = None

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
                self.speed_in = (self.traffic_in -
                                 self.last_traffic_in) * 8 / time_diff
                self.speed_out = (
                    (self.traffic_out - self.last_traffic_out) * 8 / time_diff
                )

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

    def get_stats_display(self) -> str:
        """Get formatted statistics display"""

        col_width = 30

        conns_stat = f"\033[97mTotal: \033[93m{self.total_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " + f"\033[97mMiss: \033[96m{self.allowed_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " + f"\033[97mUnblock: \033[92m{self.blocked_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " f"\033[97mErrors: \033[91m{self.errors_connections}\033[0m".ljust(
            col_width
        )

        traffic_stat = (
            f"\033[97mTotal: \033[96m{self.format_size(self.traffic_out + self.traffic_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mDL: \033[96m{self.format_size(self.traffic_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_size(self.traffic_out)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
        )

        avg_speed_in = (
            self.average_speed_in[0] / self.average_speed_in[1]
            if self.average_speed_in[1] > 0
            else 0
        )
        avg_speed_out = (
            self.average_speed_out[0] / self.average_speed_out[1]
            if self.average_speed_out[1] > 0
            else 0
        )

        speed_stat = (
            f"\033[97mDL: \033[96m{self.format_speed(self.speed_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_speed(self.speed_out)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mAVG DL: \033[96m{self.format_speed(avg_speed_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mAVG UL: \033[96m{self.format_speed(avg_speed_out)}\033[0m".ljust(
                col_width
            )
        )

        title = "STATISTICS"

        top_border = f"\033[92m{'═' * 36} {title} {'═' * 36}\033[0m"
        line_conns = f"\033[92m   {'Conns'.ljust(8)}:\033[0m {conns_stat}\033[0m"
        line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}\033[0m"
        line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}\033[0m"
        bottom_border = f"\033[92m{'═' * (36*2+len(title)+2)}\033[0m"

        return (
            f"{top_border}\n{line_conns}\n{line_traffic}\n{line_speed}\n{bottom_border}"
        )

    @staticmethod
    def format_size(size: int) -> str:
        """Convert size to human readable format"""

        units = ["B", "KB", "MB", "GB"]
        unit = 0
        size_float = float(size)
        while size_float >= 1024 and unit < len(units) - 1:
            size_float /= 1024
            unit += 1
        return f"{size_float:.1f} {units[unit]}"

    @staticmethod
    def format_speed(speed_bps: float) -> str:
        """Convert speed to human readable format"""

        if speed_bps <= 0:
            return "0 b/s"

        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"


class ConnectionHandler(IConnectionHandler):
    """Handles individual client connections"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = self.config.out_host
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection"""

        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(1500)

            if not http_data:
                writer.close()
                return

            method, host, port = self._parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(
                client_ip, host.decode(), method.decode())

            if method == b"CONNECT" and isinstance(
                self.blacklist_manager, AutoBlacklistManager
            ):
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if method == b"CONNECT":
                await self._handle_https_connection(
                    reader, writer, host, port, conn_key, conn_info
                )
            else:
                await self._handle_http_connection(
                    reader, writer, http_data, host, port, conn_key
                )

        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        """Parse HTTP request to extract method, host and port"""

        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]

        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next(
                (h for h in headers if h.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")

            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80

        return method, host, port

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: Tuple,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle HTTPS CONNECT request"""

        response_size = len(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.statistics.update_traffic(response_size, 0)
        conn_info.traffic_in += response_size

        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0)
        )

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        http_data: bytes,
        host: bytes,
        port: int,
        conn_key: Tuple,
    ) -> None:
        """Handle HTTP request"""

        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0)
        )

        remote_writer.write(http_data)
        await remote_writer.drain()

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data):
        i = 0
        while i < len(data) - 8:
            if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
                ext_len = data[i+3]
                server_name_list_len = data[i+5]
                server_name_len = data[i+8]
                if ext_len - server_name_list_len == 2 and server_name_list_len - server_name_len == 3:
                    sni_start = i + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            i += 1
        return None

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle initial TLS data and fragmentation"""

        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.log_error(
                f"{host.decode()} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(
                conn_info.dst_domain)

        if not should_fragment:
            self.statistics.increment_total_connections()
            self.statistics.increment_allowed_connections()
            combined_data = head + data
            writer.write(combined_data)
            await writer.drain()

            self.statistics.update_traffic(0, len(combined_data))
            conn_info.traffic_out += len(combined_data)
            return

        self.statistics.increment_total_connections()
        self.statistics.increment_blocked_connections()

        parts = []

        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)

            if sni_pos:
                part_start = data[:sni_pos[0]]
                sni_data = data[sni_pos[0]:sni_pos[1]]
                part_end = data[sni_pos[1]:]
                middle = (len(sni_data) + 1) // 2

                parts.append(
                    bytes.fromhex("160304") +
                    len(part_start).to_bytes(2, "big") +
                    part_start
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(sni_data[:middle]).to_bytes(2, "big") +
                    sni_data[:middle]
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(sni_data[middle:]).to_bytes(2, "big") +
                    sni_data[middle:]
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(part_end).to_bytes(2, "big") +
                    part_end
                )

        elif self.config.fragment_method == "random":
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = (
                    bytes.fromhex("160304")
                    + (host_end + 1).to_bytes(2, "big")
                    + data[: host_end + 1]
                )
                parts.append(part_data)
                data = data[host_end + 1:]

            while data:
                chunk_len = random.randint(1, len(data))
                part_data = (
                    bytes.fromhex("160304")
                    + chunk_len.to_bytes(2, "big")
                    + data[:chunk_len]
                )
                parts.append(part_data)
                data = data[chunk_len:]

        combined_parts = b"".join(parts)
        writer.write(combined_parts)
        await writer.drain()

        self.statistics.update_traffic(0, len(combined_parts))
        conn_info.traffic_out += len(combined_parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        """Setup bidirectional piping between client and remote"""

        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(
                        self._pipe_data(
                            client_reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self._pipe_data(
                            remote_reader, client_writer, "in", conn_key)
                    ),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
        """Pipe data between reader and writer"""

        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                if not data:
                    break

                if direction == "out":
                    self.statistics.update_traffic(0, len(data))
                else:
                    self.statistics.update_traffic(len(data), 0)

                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                        else:
                            conn_info.traffic_in += len(data)

                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            self.logger.log_error(
                f"{conn_info.dst_domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(
                        f"{conn_info.start_time} {conn_info.src_ip} {conn_info.method} {conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}"
                    )

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Handle connection errors"""

        try:
            error_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            writer.write(error_response)
            await writer.drain()

            self.statistics.update_traffic(len(error_response), 0)
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()
        self.logger.log_error(
            f"{conn_info.dst_domain} : {traceback.format_exc()}")

        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def cleanup_tasks(self) -> None:
        """Clean up completed tasks"""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]


class ProxyServer:
    """Main proxy server class"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(
            config, blacklist_manager, statistics, logger
        )
        self.server = None

        logger.set_error_counter_callback(
            statistics.increment_error_connections)

    def print_banner(self) -> None:
        """Print startup banner"""

        self.logger.info("\033]0;NoDPI\007")

        if sys.platform == "win32":
            os.system("mode con: lines=35")

        console_width = os.get_terminal_size().columns
        disclaimer = """DISCLAIMER. The developer and/or supplier of this software shall not be liable for any loss or damage, including but not limited to direct, indirect, incidental, punitive or consequential damages arising out of the use of or inability to use this software, even if the developer or supplier has been advised of the possibility of such damages. The developer and/or supplier of this software shall not be liable for any legal consequences arising out of the use of this software. This includes, but is not limited to, violation of laws, rules or regulations, as well as any claims or suits arising out of the use of this software. The user is solely responsible for compliance with all applicable laws and regulations when using this software."""
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)

        left_padding = (console_width - 76) // 2

        self.logger.info("\n\n\n")
        self.logger.info(
            "\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m"
        )

        for line in wrapped_text:
            padded_line = line.ljust(70)
            self.logger.info(
                "\033[91m" + " " * left_padding +
                "║ " + padded_line + " ║" + "\033[0m"
            )

        self.logger.info(
            "\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m"
        )
        time.sleep(1)
        self.logger.info('\033[2J\033[H')

        self.logger.info(
            """
\033[92m ██████   █████          ██████████   ███████████  █████
░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
 ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
 ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
 ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
 ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
 █████  ░░█████░░██████  ██████████   █████        █████
░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """
        )
        self.logger.info(f"\033[92mVersion: {__version__}".center(50))
        self.logger.info(
            "\033[97m" +
            "Enjoy watching! / Наслаждайтесь просмотром!".center(50)
        )

        self.logger.info("\n")
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Proxy is running on {self.config.host}:{self.config.port} at {datetime.now().strftime('%H:%M on %Y-%m-%d')}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m The selected fragmentation method: {self.config.fragment_method}"
        )

        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking."
            )
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains"
            )
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Path to blacklist: '{self.config.blacklist_file}'"
            )

        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Error logging is disabled")

        if self.config.log_access_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Access logging is disabled")

        self.logger.info("")
        self.logger.info(
            "\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice"
        )
        self.logger.info("")

    async def display_stats(self) -> None:
        """Display live statistics"""

        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                stats_display = self.statistics.get_stats_display()
                print(stats_display)
                print("\033[5A", end="")

    async def run(self) -> None:
        """Run the proxy server"""

        self.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start proxy on this address ({self.config.host}:{self.config.port}). It looks like the port is already in use\033[0m"
            )
            sys.exit(1)

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())

        await self.server.serve_forever()

    async def shutdown(self) -> None:
        """Shutdown the proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.connection_handler.tasks:
            task.cancel()


class BlacklistManagerFactory:
    """Factory for creating blacklist managers"""

    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        if config.no_blacklist:
            return NoBlacklistManager()
        if config.auto_blacklist:
            return AutoBlacklistManager(config)

        try:
            return FileBlacklistManager(config)
        except FileNotFoundError as e:
            logger.error(f"\033[91m[ERROR]: {e}\033[0m")
            sys.exit(1)


class ConfigLoader:
    """Loads configuration from command line arguments"""

    @staticmethod
    def load_from_args(args) -> ProxyConfig:

        config = ProxyConfig()
        config.host = args.host
        config.port = args.port
        config.out_host = args.out_host
        config.blacklist_file = args.blacklist
        config.fragment_method = args.fragment_method
        config.domain_matching = args.domain_matching
        config.log_access_file = args.log_access
        config.log_error_file = args.log_error
        config.no_blacklist = args.no_blacklist
        config.auto_blacklist = args.autoblacklist
        config.quiet = args.quiet
        return config


class WindowsAutostartManager(IAutostartManager):
    """Manages Windows autostart registry entries"""

    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        """Manages Windows autostart registry entries"""

        app_name = "NoDPIProxy"
        exe_path = sys.executable

        try:
            key = winreg.HKEY_CURRENT_USER  # pylint: disable=possibly-used-before-assignment
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

            if action == "install":
                with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(
                        regkey,
                        app_name,
                        0,
                        winreg.REG_SZ,
                        f'"{exe_path}" --blacklist "{os.path.dirname(exe_path)}/blacklist.txt"',
                    )
                print(
                    f"\033[92m[INFO]:\033[97m Added to autostart: {exe_path}")

            elif action == "uninstall":
                try:
                    with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                        winreg.DeleteValue(regkey, app_name)
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except FileNotFoundError:
                    print("\033[91m[ERROR]: Not found in autostart\033[0m")

        except PermissionError:
            print("\033[91m[ERROR]: Access denied. Run as administrator\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


class LinuxAutostartManager(IAutostartManager):

    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        """Manages Linux autostart"""

        app_name = "NoDPIProxy"
        exec_path = sys.executable

        if action == "install":
            try:
                autostart_dir = Path.home() / ".config" / "autostart"
                autostart_dir.mkdir(parents=True, exist_ok=True)

                desktop_file = autostart_dir / f"{app_name}.desktop"

                desktop_content = ("[Desktop Entry]"
                                   "\nType=Application"
                                   f"\nName={app_name}"
                                   f"\nExec={exec_path} --blacklist '{os.path.dirname(exec_path)}/blacklist.txt'"
                                   "\nHidden=false"
                                   "\nNoDisplay=false"
                                   "\nX-GNOME-Autostart-enabled=true")

                with open(desktop_file, "w", encoding="utf-8") as f:
                    f.write(desktop_content)

                print(
                    f"\033[92m[INFO]:\033[97m Added to autostart: {exec_path}")

            except Exception as e:
                print(
                    f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")

        elif action == "uninstall":
            autostart_dir = Path.home() / ".config" / "autostart"
            desktop_file = autostart_dir / f"{app_name}.desktop"

            if desktop_file.exists():
                try:
                    desktop_file.unlink()
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except Exception as e:
                    print(
                        f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


class ProxyApplication:
    """Main application class"""

    @staticmethod
    def parse_args():
        """Parse command line arguments"""

        parser = argparse.ArgumentParser()
        parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
        parser.add_argument("--port", type=int,
                            default=8881, help="Proxy port")
        parser.add_argument(
            "--out-host", default="127.0.0.1", help="Outgoing proxy host"
        )

        blacklist_group = parser.add_mutually_exclusive_group()
        blacklist_group.add_argument(
            "--blacklist", default="blacklist.txt", help="Path to blacklist file"
        )
        blacklist_group.add_argument(
            "--no-blacklist",
            action="store_true",
            help="Use fragmentation for all domains",
        )
        blacklist_group.add_argument(
            "--autoblacklist",
            action="store_true",
            help="Automatic detection of blocked domains",
        )

        parser.add_argument("--fragment-method", default="random", choices=[
                            "random", "sni"], help="Fragmentation method (random by default)")
        parser.add_argument("--domain-matching", default="strict",
                            choices=["loose", "strict"], help="Domain matching mode (strict by default)")
        parser.add_argument(
            "--log-access", required=False, help="Path to the access control log"
        )
        parser.add_argument(
            "--log-error", required=False, help="Path to log file for errors"
        )
        parser.add_argument(
            "-q", "--quiet", action="store_true", help="Remove UI output"
        )

        autostart_group = parser.add_mutually_exclusive_group()
        autostart_group.add_argument(
            "--install",
            action="store_true",
            help="Add proxy to Windows/Linux autostart (only for executable version)",
        )
        autostart_group.add_argument(
            "--uninstall",
            action="store_true",
            help="Remove proxy from Windows/Linux autostart (only for executable version)",
        )

        return parser.parse_args()

    @classmethod
    async def run(cls):
        """Run the proxy application"""

        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        args = cls.parse_args()

        if args.install or args.uninstall:
            if getattr(sys, "frozen", False):
                if args.install:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("install")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("install")
                elif args.uninstall:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("uninstall")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("uninstall")
                sys.exit(0)
            else:
                print(
                    "\033[91m[ERROR]: Autostart works only in executable version\033[0m")
                sys.exit(1)

        config = ConfigLoader.load_from_args(args)

        logger = ProxyLogger(
            config.log_access_file, config.log_error_file, config.quiet
        )
        blacklist_manager = BlacklistManagerFactory.create(config, logger)
        statistics = Statistics()

        logger.set_error_counter_callback(
            statistics.increment_error_connections)

        proxy = ProxyServer(config, blacklist_manager, statistics, logger)

        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            logger.info(
                "\n"*6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
