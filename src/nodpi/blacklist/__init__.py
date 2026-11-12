"""Blacklist managers and the factory choosing one from the config"""

import sys

from nodpi.blacklist.auto import AutoBlacklistManager
from nodpi.blacklist.file import FileBlacklistManager
from nodpi.blacklist.none import NoBlacklistManager
from nodpi.config import ProxyConfig
from nodpi.interfaces import IBlacklistManager, ILogger

__all__ = [
    "AutoBlacklistManager",
    "FileBlacklistManager",
    "NoBlacklistManager",
    "create_blacklist_manager",
]


def create_blacklist_manager(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
    """Create the blacklist manager selected by the config"""

    if config.no_blacklist:
        return NoBlacklistManager()
    if config.auto_blacklist:
        return AutoBlacklistManager(config)

    try:
        return FileBlacklistManager(config)
    except FileNotFoundError as e:
        logger.fatal(str(e))
        sys.exit(1)
