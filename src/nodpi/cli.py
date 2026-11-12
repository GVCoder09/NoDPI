"""Command line arguments"""

import argparse
from typing import List, Optional

from nodpi.config import ProxyConfig


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser"""

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
    parser.add_argument("--port", type=int, default=8881, help="Proxy port")
    parser.add_argument("--out-host", help="Outgoing proxy host")

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

    parser.add_argument(
        "--no-disorder",
        dest="disordering",
        action="store_false",
        help="Disable disordering",
    )
    parser.add_argument(
        "--no-retry",
        dest="retries",
        action="store_false",
        help="Do not retry the ClientHello over new connections when the server is silent",
    )
    parser.add_argument(
        "--domain-matching",
        default="strict",
        choices=["loose", "strict"],
        help="Domain matching mode (strict by default)",
    )

    parser.add_argument("--auth-username", required=False, help="Username for proxy authentication")
    parser.add_argument("--auth-password", required=False, help="Password for proxy authentication")

    parser.add_argument("--log-access", required=False, help="Path to the access control log")
    parser.add_argument("--log-error", required=False, help="Path to log file for errors")
    parser.add_argument("-q", "--quiet", action="store_true", help="Remove UI output")
    parser.add_argument(
        "--start-in-tray",
        action="store_true",
        help="Start minimized to tray (Windows only)",
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

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments"""

    return build_parser().parse_args(argv)


def config_from_args(args: argparse.Namespace) -> ProxyConfig:
    """Build ProxyConfig from parsed arguments"""

    config = ProxyConfig()
    config.host = args.host
    config.port = args.port
    config.out_host = args.out_host
    config.username = args.auth_username
    config.password = args.auth_password
    config.blacklist_file = args.blacklist
    config.disordering = args.disordering
    config.retries = args.retries
    config.domain_matching = args.domain_matching
    config.log_access_file = args.log_access
    config.log_error_file = args.log_error
    config.no_blacklist = args.no_blacklist
    config.auto_blacklist = args.autoblacklist
    config.quiet = args.quiet
    config.start_in_tray = args.start_in_tray
    return config
