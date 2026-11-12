"""Listening proxy server"""

import asyncio
import sys
from typing import Optional

from nodpi.config import ProxyConfig
from nodpi.dns import Resolver
from nodpi.interfaces import IBlacklistManager, ILogger
from nodpi.proxy.handler import ConnectionHandler
from nodpi.statistics import Statistics
from nodpi.ui.banner import print_disclaimer, print_main_screen
from nodpi.ui.stats_view import render_stats
from nodpi.updates import get_update_message


class ProxyServer:
    """Main proxy server class"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: Statistics,
        logger: ILogger,
        resolver: Resolver,
    ):

        self.config = config
        self.resolver = resolver
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(
            config, blacklist_manager, statistics, logger, resolver
        )
        self.server: Optional[asyncio.AbstractServer] = None

    async def print_banner(self) -> None:
        """Print startup banner"""

        update_message = await get_update_message()
        print_disclaimer(self.logger)
        print_main_screen(
            self.logger, self.config, self.blacklist_manager, self.resolver, update_message
        )

    async def display_stats(self) -> None:
        """Display live statistics"""

        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                print(render_stats(self.statistics))
                print("\033[5A", end="")

    async def run(self) -> None:
        """Run the proxy server"""

        if not self.config.quiet:
            await self.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.fatal(
                f"Failed to start proxy on this address "
                f"({self.config.host}:{self.config.port}). "
                f"It looks like the port is already in use"
            )
            if not self.config.quiet and sys.stdin is not None and sys.stdin.isatty():
                input("\nPress Enter to exit...")

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
