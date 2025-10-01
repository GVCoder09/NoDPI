#!/usr/bin/env python3

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

from urllib.error import URLError
from datetime import datetime
from urllib.request import urlopen, Request

if sys.platform == "win32":
    import winreg

__version__ = "1.9"

os.system("")


class ConnectionInfo:
    """ Class to store connection information """

    def __init__(self, src_ip, dst_domain, method):
        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0


class ProxyServer:
    """ Class to handle the proxy server """

    def __init__(self, host, port, out_host,
                 blacklist, log_access, log_err, no_blacklist, auto_blacklist, quiet):

        self.host = host
        self.port = port
        self.out_host = out_host
        self.blacklist = blacklist
        self.log_access_file = log_access
        self.log_err_file = log_err
        self.no_blacklist = no_blacklist
        self.auto_blacklist = auto_blacklist
        self.quiet = quiet

        self.logger = logging.getLogger(__name__)
        self.logging_errors = None
        self.logging_access = None

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

        self.active_connections = {}
        self.connections_lock = asyncio.Lock()
        self.tasks_lock = asyncio.Lock()

        self.blocked = []
        self.whitelist = []
        self.tasks = []
        self.server = None

        self.setup_logging()
        self.load_blacklist()

    def print(self, *args, **kwargs):
        """
        Print the given arguments if quiet mode is enabled.

        Parameters:
            **kwargs: Any arguments accepted by the built-in print() function.
        """

        if not self.quiet:
            print(*args, **kwargs)

    def setup_logging(self):
        """
        Set up the logging configuration.

        The logging level is set to ERROR and the log messages are written to the
        file specified by the log_file parameter. The log format is
        [%(asctime)s][%(levelname)s]: %(message)s and the date format is
        %Y-%m-%d %H:%M:%S.
        """

        class ErrorCounterHandler(logging.FileHandler):
            """ Handler for logging errors """

            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback

            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.counter_callback()
                super().emit(record)

        if self.log_err_file:
            self.logging_errors = ErrorCounterHandler(
                lambda: setattr(self, 'errors_connections',
                                self.errors_connections + 1),
                self.log_err_file, encoding='utf-8'
            )
            self.logging_errors.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"
                )
            )
            self.logging_errors.setLevel(logging.ERROR)
            self.logging_errors.addFilter(
                lambda record: record.levelno == logging.ERROR
            )
        else:
            self.logging_errors = logging.NullHandler()

        if self.log_access_file:
            self.logging_access = logging.FileHandler(
                self.log_access_file, encoding='utf-8')

            self.logging_access.setFormatter(logging.Formatter("%(message)s"))
            self.logging_access.setLevel(logging.INFO)
            self.logging_access.addFilter(
                lambda record: record.levelno == logging.INFO)
        else:
            self.logging_access = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.logging_errors)
        self.logger.addHandler(self.logging_access)

    def load_blacklist(self):
        """
        Load the blacklist from the specified file.
        """

        if self.no_blacklist or self.auto_blacklist:
            return
        if not os.path.exists(self.blacklist):
            self.print(
                f"\033[91m[ERROR]: File {self.blacklist} not found\033[0m")
            self.logger.error("File %s not found", self.blacklist)
            sys.exit(1)

        with open(self.blacklist, "r", encoding="utf-8") as f:
            self.blocked = [line.rstrip().encode() for line in f]

    async def run(self):
        """
        Start the proxy server and run it until it is stopped.

        This method starts the proxy server by calling
        `asyncio.start_server` with the `handle_connection` method as the
        protocol handler. The server is then started with the `serve_forever`
        method.
        """

        self.print_info()
        if not self.quiet:
            asyncio.create_task(self.display_stats())
        try:
            self.server = await asyncio.start_server(
                self.handle_connection, self.host, self.port
            )
        except OSError:
            self.print(
                f"\033[91m[ERROR]: Failed to start proxy on this address ({self.host}:{self.port}). It looks like the port is already in use\033[0m")
            self.logger.error("Port %s is already in use", self.port)
            sys.exit(1)

        asyncio.create_task(self.cleanup_tasks())
        await self.server.serve_forever()

    def print_info(self):
        """
        Print a banner with the NoDPI logo and information about the proxy.
        """

        if sys.platform == "win32":
            os.system("mode con: lines=35")

        console_width = os.get_terminal_size().columns
        disclaimer = """DISCLAIMER. The developer and/or supplier of this software shall not be liable for any loss or damage, including but not limited to direct, indirect, incidental, punitive or consequential damages arising out of the use of or inability to use this software, even if the developer or supplier has been advised of the possibility of such damages. The developer and/or supplier of this software shall not be liable for any legal consequences arising out of the use of this software. This includes, but is not limited to, violation of laws, rules or regulations, as well as any claims or suits arising out of the use of this software. The user is solely responsible for compliance with all applicable laws and regulations when using this software."""
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)

        left_padding = (console_width - 76) // 2

        self.print('\033[91m' + ' ' * left_padding +
                   '╔' + '═' * 72 + '╗' + '\033[0m')

        for line in wrapped_text:
            padded_line = line.ljust(70)
            print('\033[91m' + ' ' * left_padding +
                  '║ ' + padded_line + ' ║' + '\033[0m', flush=True)

        self.print('\033[91m' + ' ' * left_padding +
                   '╚' + '═' * 72 + '╝' + '\033[0m')
        time.sleep(1)
        self.print('\033[2J\033[H')

        self.print(
            '''
\033[92m ██████   █████          ██████████   ███████████  █████
░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
 ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
 ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
 ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
 ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
 █████  ░░█████░░██████  ██████████   █████        █████
░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        '''
        )
        self.print(f"\033[92mVersion: {__version__}".center(50))
        self.print(
            "\033[97m" +
            "Enjoy watching! / Наслаждайтесь просмотром!".center(50)
        )

        self.print("\n")
        self.print(
            f"\033[92m[INFO]:\033[97m Proxy is running on {self.host}:{self.port} at {datetime.now().strftime('%H:%M on %Y-%m-%d')}"
        )

        self.print()
        if self.no_blacklist:
            self.print(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking.")
        elif self.auto_blacklist:
            self.print(
                "\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.print(
                f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blocked)} domains"
            )
            self.print(
                f"\033[92m[INFO]:\033[97m Path to blacklist: '{self.blacklist}'"
            )

        self.print()
        if self.log_err_file:
            self.print(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.log_err_file}'"
            )
        else:
            self.print("\033[92m[INFO]:\033[97m Error logging is disabled")
        if self.log_access_file:
            self.print(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.log_access_file}'"
            )
        else:
            self.print("\033[92m[INFO]:\033[97m Access logging is disabled")

        self.print()
        self.print(
            "\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice")
        self.print()

    async def display_stats(self):
        """
        Display the current statistics of the proxy server.
        """

        while True:
            await asyncio.sleep(1)
            current_time = time.time()

            if self.last_time is not None:
                time_diff = current_time - self.last_time
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

            col_width = 30

            conns_stat = (
                f"\033[97mTotal: \033[93m{self.total_connections}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mMiss: \033[96m{self.allowed_connections}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mUnblock: \033[92m{self.blocked_connections}\033[0m".ljust(
                    col_width) + "\033[97m| "
                f"\033[97mErrors: \033[91m{self.errors_connections}\033[0m".ljust(
                    col_width)
            )

            traffic_stat = (
                f"\033[97mTotal: \033[96m{self.format_size(self.traffic_out + self.traffic_in)}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mDL: \033[96m{self.format_size(self.traffic_in)}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mUL: \033[96m{self.format_size(self.traffic_out)}\033[0m".ljust(
                    col_width) + "\033[97m| "
            )

            speed_stat = (
                f"\033[97mDL: \033[96m{self.format_speed(self.speed_in)}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mUL: \033[96m{self.format_speed(self.speed_out)}\033[0m".ljust(
                    col_width) + "\033[97m| " +
                f"\033[97mAVG DL: \033[96m{self.format_speed(self.average_speed_in[0] / self.average_speed_in[1])}\033[0m".ljust(col_width) + "\033[97m| " +
                f"\033[97mAVG UL: \033[96m{self.format_speed(self.average_speed_out[0] / self.average_speed_out[1])}\033[0m".ljust(
                    col_width)
            )

            title = "STATISTICS"

            top_border = f"\033[92m{'═' * 36} {title} {'═' * 36}\033[0m"
            line_conns = f"\033[92m   {'Conns'.ljust(8)}:\033[0m {conns_stat}\033[0m"
            line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}\033[0m"
            line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}\033[0m"
            bottom_border = f"\033[92m{'═' * (36*2+len(title)+2)}\033[0m"

            stats_block = f"{top_border}\n{line_conns}\n{line_traffic}\n{line_speed}\n{bottom_border}"

            self.print(stats_block)
            self.print("\u001b[1F"*5, end="")

    @staticmethod
    def format_size(size):
        """
        Convert a size in bytes to a human-readable string with appropriate units.
        """
        units = ["B", "KB", "MB", "GB"]
        unit = 0
        while size >= 1024 and unit < len(units) - 1:
            size /= 1024
            unit += 1
        return f"{size:.1f} {units[unit]}"

    @staticmethod
    def format_speed(speed_bps):
        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"

    async def cleanup_tasks(self):
        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]

    async def handle_connection(self, reader, writer):
        """
        Handle a connection from a client.

        This method is called when a connection is accepted from a client. It reads
        the initial HTTP data from the client and tries to parse it as a CONNECT
        request. If the request is valid, it opens a connection to the target
        server and starts piping data between the client and the target server.
        """

        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(1500)
            if not http_data:
                writer.close()
                return
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
                    (h for h in headers if h.startswith(b"Host: ")), None
                )
                if not host_header:
                    raise ValueError("Missing Host header")

                host_port = host_header[6:].split(b":")
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 80

            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(
                client_ip, host.decode(), method.decode())

            if method == b"CONNECT" and self.auto_blacklist:
                try:
                    if host not in self.blocked and host not in self.whitelist:
                        req = Request(
                            'https://' + host.decode(), headers={'User-Agent': 'Mozilla/5.0'})
                        context = ssl._create_unverified_context()  # pylint: disable=protected-access

                        with urlopen(req, timeout=4, context=context):
                            self.whitelist.append(host)
                except URLError as e:
                    reason = str(e.reason)
                    if "handshake operation timed out" in reason:
                        self.blocked.append(host)
                        with open(self.blacklist, "a", encoding="utf-8") as f:
                            f.write(host.decode() + "\n")

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            if method == b"CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

                remote_reader, remote_writer = await asyncio.open_connection(
                    host.decode(), port, local_addr=(self.out_host, 0)
                )

                await self.fragment_data(reader, remote_writer)
            else:
                remote_reader, remote_writer = await asyncio.open_connection(
                    host.decode(), port, local_addr=(self.out_host, 0)
                )
                remote_writer.write(http_data)
                await remote_writer.drain()

                self.allowed_connections += 1

            self.total_connections += 1

            self.tasks.extend(
                [
                    asyncio.create_task(
                        self.pipe(reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self.pipe(remote_reader, writer, "in", conn_key)
                    ),
                ]
            )
        except Exception:
            try:
                writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            try:
                host_err = host
            except Exception:
                host_err = "Unknown"

            self.logger.error("%s: %s", host_err.decode(),
                              traceback.format_exc())

            writer.close()

    async def pipe(self, reader, writer, direction, conn_key):
        """
        Pipe data from a reader to a writer.

        This function reads data from a reader and writes it to a writer until
        the reader is closed or the writer is closed. If an error occurs during
        the transfer, the error is logged and the writer is closed.

        Parameters:
            reader (asyncio.StreamReader): The reader to read from
            writer (asyncio.StreamWriter): The writer to write to
            direction (str): The direction of the transfer (in or out)
            conn_key (tuple): The connection key
        """

        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            self.traffic_out += len(data)
                            conn_info.traffic_out += len(data)
                        else:
                            self.traffic_in += len(data)
                            conn_info.traffic_in += len(data)
                writer.write(data)
                await writer.drain()
        except Exception:
            host_err = conn_info.dst_domain
            self.logger.error("%s: %s", host_err.decode(),
                              traceback.format_exc())
        finally:
            writer.close()
            async with self.connections_lock:
                conn_info: ConnectionInfo = self.active_connections.pop(
                    conn_key, None)
                if conn_info:
                    self.logger.info(
                        "%s %s %s %s",
                        conn_info.start_time, conn_info.src_ip, conn_info.method, conn_info.dst_domain
                    )

    async def fragment_data(self, reader, writer):
        """
        Fragment data from a reader and write it to a writer.

        This function reads data from a reader and fragments it according to the
        blocked sites list. If the data does not contain any blocked sites, it is
        written to the writer as is. Otherwise, it is split into chunks and each
        chunk is written to the writer as a separate TLS record.

        Parameters:
            reader (asyncio.StreamReader): The reader to read from
            writer (asyncio.StreamWriter): The writer to write to
        """

        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.error(traceback.format_exc())
            return

        if not self.no_blacklist and all(site not in data for site in self.blocked):
            self.allowed_connections += 1
            writer.write(head + data)
            await writer.drain()
            return

        self.blocked_connections += 1

        parts = []
        host_end = data.find(b"\x00")
        if host_end != -1:
            parts.append(
                bytes.fromhex("160304")
                + (host_end + 1).to_bytes(2, "big")
                + data[: host_end + 1]
            )
            data = data[host_end + 1:]

        while data:
            chunk_len = random.randint(1, len(data))
            parts.append(
                bytes.fromhex("160304")
                + chunk_len.to_bytes(2, "big")
                + data[:chunk_len]
            )
            data = data[chunk_len:]

        writer.write(b"".join(parts))
        await writer.drain()

    async def shutdown(self):
        """
        Shutdown the proxy server.

        This function closes the server and cancels all tasks running on the
        event loop. If a server is not running, the function does nothing.
        """

        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in self.tasks:
            task.cancel()


class ProxyApplication:
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
        parser.add_argument("--port", type=int,
                            default=8881, help="Proxy port")
        parser.add_argument("--out_host", default="127.0.0.1",
                            help="Outgoing proxy host")

        blacklist_group = parser.add_mutually_exclusive_group()
        blacklist_group.add_argument(
            "--blacklist", default="blacklist.txt", help="Path to blacklist file"
        )
        blacklist_group.add_argument(
            "--no_blacklist", action="store_true", help="Use fragmentation for all domains"
        )
        blacklist_group.add_argument(
            "--autoblacklist", action="store_true", help="Automatic detection of blocked domains"
        )

        parser.add_argument(
            "--log_access", required=False, help="Path to the access control log"
        )
        parser.add_argument(
            "--log_error", required=False, help="Path to log file for errors"
        )
        parser.add_argument(
            "-q", "--quiet", action="store_true", help="Remove UI output"
        )

        autostart_group = parser.add_mutually_exclusive_group()
        autostart_group.add_argument(
            "--install",
            action="store_true",
            help="Add proxy to Windows autostart (only for EXE)",
        )
        autostart_group.add_argument(
            "--uninstall",
            action="store_true",
            help="Remove proxy from Windows autostart (only for EXE)",
        )

        return parser.parse_args()

    @staticmethod
    def manage_autostart(action="install"):
        """ Manage proxy autostart on Windows

            Parameters:
                action (str): "install" or "uninstall"
        """

        if sys.platform != "win32":
            print(
                "\033[91m[ERROR]:\033[97m Autostart only available on Windows")
            return

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

    @classmethod
    async def run(cls):
        """
        Run the proxy server
        """

        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        args = cls.parse_args()

        if args.install or args.uninstall:
            if getattr(sys, 'frozen', False):
                if args.install:
                    cls.manage_autostart("install")
                elif args.uninstall:
                    cls.manage_autostart("uninstall")
                sys.exit(0)
            else:
                print(
                    "\033[91m[ERROR]: Autostart works only in EXE version\033[0m")
                sys.exit(1)

        proxy = ProxyServer(
            args.host,
            args.port,
            args.out_host,
            args.blacklist,
            args.log_access,
            args.log_error,
            args.no_blacklist,
            args.autoblacklist,
            args.quiet,
        )

        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            proxy.print("\n\n\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                sys.exit(0)
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
