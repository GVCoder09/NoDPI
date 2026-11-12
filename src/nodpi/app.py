"""Application wiring: parse arguments, build components, run the server"""

import asyncio
import contextlib
import logging
import os
import sys

from nodpi import __version__
from nodpi.autostart import manage_autostart
from nodpi.blacklist import create_blacklist_manager
from nodpi.cli import config_from_args, parse_args
from nodpi.logger import ProxyLogger
from nodpi.proxy.server import ProxyServer
from nodpi.statistics import Statistics


def _handle_autostart(install: bool) -> None:
    """--install / --uninstall: only supported for the frozen executable"""

    if not getattr(sys, "frozen", False):
        print("\033[91m[ERROR]: Autostart works only in executable version\033[0m")
        sys.exit(1)

    manage_autostart("install" if install else "uninstall")
    sys.exit(0)


def _start_tray(start_hidden: bool) -> None:
    """Windows only: tray icon with minimize-to-tray"""

    from nodpi.ui.tray import WindowsTrayIcon  # pylint: disable=import-outside-toplevel

    tray = WindowsTrayIcon(tooltip=f"NoDPI v{__version__}")
    tray.start()
    if start_hidden:
        tray.hide_to_tray()


async def run() -> None:
    """Run the proxy application"""

    logging.getLogger("asyncio").setLevel(logging.CRITICAL)

    args = parse_args()

    if args.install or args.uninstall:
        _handle_autostart(args.install)

    config = config_from_args(args)

    logger = ProxyLogger(config.log_access_file, config.log_error_file, config.quiet)
    blacklist_manager = create_blacklist_manager(config, logger)
    statistics = Statistics()

    logger.set_error_counter_callback(statistics.increment_error_connections)

    if sys.platform == "win32" and not config.quiet:
        _start_tray(config.start_in_tray)

    proxy = ProxyServer(config, blacklist_manager, statistics, logger)

    try:
        await proxy.run()
    except asyncio.CancelledError:
        await proxy.shutdown()
        logger.info("\n" * 6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
        try:
            if sys.platform == "win32":
                os.system("mode con: lines=3000")
            sys.exit(0)
        except asyncio.CancelledError:
            pass


def _configure_console() -> None:
    """Make console output safe: UTF-8 where possible, never crash on encoding"""

    for stream in (sys.stdout, sys.stderr):
        # AttributeError/ValueError: not a regular text stream (e.g. a GUI wrapper)
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    """Console entry point"""

    if sys.platform == "win32":
        os.system("")  # enable ANSI escape sequences in the Windows console
        _configure_console()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run())
