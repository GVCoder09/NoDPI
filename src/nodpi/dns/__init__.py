"""Name resolution: DNS over HTTPS with the system resolver as fallback"""

from typing import Callable, List, Optional

from nodpi.dns.doh import DohServer
from nodpi.dns.resolver import Resolver, builtin_servers, is_local_name

__all__ = ["DohServer", "Resolver", "build_resolver", "is_local_name"]


def build_resolver(
    use_doh: bool,
    custom_urls: List[str],
    local_host: Optional[str] = None,
    on_error: Optional[Callable[[str], None]] = None,
) -> Resolver:
    """Custom servers first, then Google and Cloudflare; raises ValueError on a bad URL"""

    custom = [DohServer(url, local_host=local_host) for url in custom_urls]
    return Resolver(custom + builtin_servers(local_host), use_doh, on_error)
