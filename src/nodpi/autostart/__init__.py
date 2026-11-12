"""Autostart (Windows registry / Linux systemd user service)"""

import sys


def manage_autostart(action: str) -> None:
    """Install or uninstall autostart for the current platform.

    ``action`` is "install" or "uninstall". Other platforms are ignored.
    """

    if sys.platform == "win32":
        from nodpi.autostart.windows import WindowsAutostartManager  # pylint: disable=import-outside-toplevel

        WindowsAutostartManager.manage_autostart(action)
    elif sys.platform == "linux":
        from nodpi.autostart.linux import LinuxAutostartManager  # pylint: disable=import-outside-toplevel

        LinuxAutostartManager.manage_autostart(action)
