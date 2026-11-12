"""Handling of a single client connection: routing, ClientHello, piping"""

import asyncio
import traceback

from typing import Dict, List, Tuple

from nodpi.config import ProxyConfig
from nodpi.interfaces import (
    IBlacklistManager,
    IConnectionHandler,
    ILogger,
    IStatistics,
)
from nodpi.proxy import http
from nodpi.proxy.connection import ConnectionInfo
from nodpi.proxy.desync import send_fragments
from nodpi.proxy.tls import TLS_HANDSHAKE, TLS_RECORD_HEADER_LEN, fragment_client_hello

READ_CHUNK = 1500

ConnKey = Tuple[str, int]


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
        self.auth_enabled = config.username is not None and config.password is not None
        self.active_connections: Dict[ConnKey, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    # ------------------------------------------------------------------ entry

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection"""

        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(READ_CHUNK)

            if not http_data:
                writer.close()
                return

            method, host, port = http.parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(
                client_ip, host.decode(), method.decode())

            if method == b"CONNECT":
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if not await self._check_proxy_authorization(http_data, writer):
                return

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

    async def _check_proxy_authorization(
        self, http_data: bytes, writer: asyncio.StreamWriter
    ) -> bool:
        """Check proxy authorization, answer 407 and close on failure"""

        if not self.auth_enabled:
            return True

        if http.check_basic_auth(http_data, self.config.username, self.config.password):
            return True

        writer.write(http.PROXY_AUTH_REQUIRED)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return False

    # ------------------------------------------------------------- upstream

    async def _open_upstream(
        self, host: bytes, port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.open_connection(
            host.decode(),
            port,
            local_addr=(self.out_host, 0) if self.out_host else None,
        )

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: ConnKey,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle HTTPS CONNECT request"""

        response_size = len(http.CONNECTION_ESTABLISHED)
        self.statistics.update_traffic(response_size, 0)
        conn_info.traffic_in += response_size

        remote_reader, remote_writer = await self._open_upstream(host, port)

        writer.write(http.CONNECTION_ESTABLISHED)
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
        conn_key: ConnKey,
    ) -> None:
        """Handle plain HTTP request"""

        remote_reader, remote_writer = await self._open_upstream(host, port)

        remote_writer.write(http_data)
        await remote_writer.drain()

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    # ---------------------------------------------------------- ClientHello

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        conn_info: ConnectionInfo,
    ) -> None:
        """Read the ClientHello from the client and forward it, fragmented if needed"""

        try:
            head = await reader.readexactly(TLS_RECORD_HEADER_LEN)
            if head[0] != TLS_HANDSHAKE:
                writer.write(head)
                await writer.drain()
                self.statistics.update_traffic(0, len(head))
                conn_info.traffic_out += len(head)
                return
            record_len = int.from_bytes(head[3:5], "big")
            data = await reader.readexactly(record_len)
        except Exception:
            self.logger.log_error(
                f"{host.decode()} : {traceback.format_exc()}")
            self.statistics.increment_error_connections()
            return

        self.statistics.increment_total_connections()

        if not self.blacklist_manager.is_blocked(conn_info.dst_domain):
            self.statistics.increment_allowed_connections()
            combined_data = head + data
            writer.write(combined_data)
            await writer.drain()

            self.statistics.update_traffic(0, len(combined_data))
            conn_info.traffic_out += len(combined_data)
            return

        self.statistics.increment_blocked_connections()

        parts = fragment_client_hello(head, data)
        await send_fragments(writer, parts, self.config.disordering)

        sent = sum(len(p) for p in parts)
        self.statistics.update_traffic(0, sent)
        conn_info.traffic_out += sent

    # --------------------------------------------------------------- piping

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: ConnKey,
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
        conn_key: ConnKey,
    ) -> None:
        """Pipe data between reader and writer"""

        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(READ_CHUNK)
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
            self.statistics.increment_error_connections()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except BaseException:  # also swallow CancelledError while closing
                pass

            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(conn_info.access_log_line())

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: ConnKey
    ) -> None:
        """Answer 500, count the error and close the client connection"""

        try:
            writer.write(http.INTERNAL_SERVER_ERROR)
            await writer.drain()

            self.statistics.update_traffic(len(http.INTERNAL_SERVER_ERROR), 0)
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
        except BaseException:  # also swallow CancelledError while closing
            pass

    async def cleanup_tasks(self) -> None:
        """Periodically drop finished piping tasks"""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]
