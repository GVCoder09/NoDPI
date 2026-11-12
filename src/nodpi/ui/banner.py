"""Startup screen: disclaimer, logo and configuration summary"""

import os
import sys
import textwrap
import time

from datetime import datetime
from typing import Optional

from nodpi import __version__
from nodpi.config import ProxyConfig
from nodpi.interfaces import IBlacklistManager, ILogger

DISCLAIMER = (
    "DISCLAIMER. The developer and/or supplier of this software "
    "shall not be liable for any loss or damage, including but "
    "not limited to direct, indirect, incidental, punitive or "
    "consequential damages arising out of the use of or inability "
    "to use this software, even if the developer or supplier has been "
    "advised of the possibility of such damages. The developer and/or "
    "supplier of this software shall not be liable for any legal "
    "consequences arising out of the use of this software. This includes, "
    "but is not limited to, violation of laws, rules or regulations, "
    "as well as any claims or suits arising out of the use of this software. "
    "The user is solely responsible for compliance with all applicable laws "
    "and regulations when using this software."
)

LOGO = """
\033[92m  ██████   █████          ██████████   ███████████  █████
 ░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
  ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
  ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
  ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
  ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
  █████  ░░█████░░██████  ██████████   █████        █████
 ░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """

INFO = "\033[92m[INFO]:\033[97m "


def print_disclaimer(logger: ILogger) -> None:
    """Show the disclaimer box for a second"""

    logger.info("\033]0;NoDPI\007")

    if sys.platform == "win32":
        os.system("mode con: lines=33")

    if sys.stdout.isatty():
        console_width = os.get_terminal_size().columns
    else:
        console_width = 80

    wrapped_text = textwrap.TextWrapper(width=70).wrap(DISCLAIMER)
    left_padding = (console_width - 76) // 2

    logger.info("\n\n\n")
    logger.info("\033[91m" + " " * left_padding +
                "╭" + "─" * 72 + "╮" + "\033[0m")
    for line in wrapped_text:
        logger.info(
            "\033[91m" + " " * left_padding +
            "│ " + line.ljust(70) + " │" + "\033[0m"
        )
    logger.info("\033[91m" + " " * left_padding +
                "╰" + "─" * 72 + "╯" + "\033[0m")

    time.sleep(1)


def print_main_screen(
    logger: ILogger,
    config: ProxyConfig,
    blacklist_manager: IBlacklistManager,
    update_message: Optional[str],
) -> None:
    """Clear the screen and show logo, version and configuration summary"""

    logger.info("\033[2J\033[H")
    logger.info(LOGO)
    logger.info(f"\033[92mVersion: {__version__}".center(50))
    logger.info(
        "\033[97m" + "Enjoy watching! / Наслаждайтесь просмотром!".center(50))
    logger.info("\n")

    if update_message:
        logger.info(update_message)

    logger.info(
        f"{INFO}Proxy is running on {config.host}:{config.port} "
        f"at {datetime.now().strftime('%H:%M on %Y-%m-%d')}"
    )

    logger.info("")
    for line in blacklist_manager.describe():
        logger.info(INFO + line)

    logger.info("")
    if config.log_error_file:
        logger.info(
            f"{INFO}Error logging is enabled. Path to error log: '{config.log_error_file}'")
    else:
        logger.info(f"{INFO}Error logging is disabled")

    if config.log_access_file:
        logger.info(
            f"{INFO}Access logging is enabled. Path to access log: '{config.log_access_file}'")
    else:
        logger.info(f"{INFO}Access logging is disabled")

    logger.info("")
    logger.info(f"{INFO}To stop the proxy, press Ctrl+C twice")
    logger.info("")
