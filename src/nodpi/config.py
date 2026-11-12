"""Proxy configuration"""

from typing import Optional


class ProxyConfig:
    """Configuration container for proxy settings"""

    def __init__(self):

        self.host = "127.0.0.1"
        self.port = 8881
        self.out_host: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.blacklist_file = "blacklist.txt"
        self.disordering = True
        self.retries = True
        self.skip_dead_hosts = True
        self.domain_matching = "strict"
        self.log_access_file: Optional[str] = None
        self.log_error_file: Optional[str] = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False
        self.start_in_tray = False
