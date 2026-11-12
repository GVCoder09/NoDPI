"""Check whether a newer NoDPI release is available"""

import asyncio
import json
from typing import Optional
from urllib.request import Request, urlopen

from nodpi import __version__

UPDATE_INFO_URL = "https://gvcoder09.github.io/nodpi_site/api/v1/update_info.json"


def fetch_latest_version(timeout: float = 3) -> Optional[str]:
    """Return the latest version if it differs from the running one (blocking)"""

    try:
        with urlopen(Request(UPDATE_INFO_URL), timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read())
                latest_version = data.get("nodpi", "").get("latest_version", "")
                if latest_version and latest_version != __version__:
                    return latest_version
    except Exception:
        pass
    return None


async def get_update_message(wait: float = 2.0) -> Optional[str]:
    """Banner line about an available update, or None.

    Waits at most ``wait`` seconds so a slow network does not delay startup.
    """

    loop = asyncio.get_event_loop()
    try:
        latest_version = await asyncio.wait_for(
            loop.run_in_executor(None, fetch_latest_version), timeout=wait
        )
    except (asyncio.TimeoutError, Exception):
        return None

    if latest_version:
        return f"\033[93m[UPDATE]: Available new version: v{latest_version} \033[97m"
    return None
