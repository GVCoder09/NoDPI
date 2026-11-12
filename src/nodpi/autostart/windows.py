"""Windows autostart via the HKCU Run registry key"""

import os
import sys

from nodpi.interfaces import IAutostartManager

APP_NAME = "NoDPIProxy"
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


class WindowsAutostartManager(IAutostartManager):
    """Manages Windows autostart registry entries"""

    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        """Manages Windows autostart registry entries"""

        import winreg  # pylint: disable=import-outside-toplevel,import-error

        exe_path = sys.executable

        try:
            key = winreg.HKEY_CURRENT_USER

            if action == "install":
                with winreg.OpenKey(key, REG_PATH, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(
                        regkey,
                        APP_NAME,
                        0,
                        winreg.REG_SZ,
                        f'"{exe_path}" --blacklist "{os.path.dirname(exe_path)}/blacklist.txt" --start-in-tray',
                    )
                print(
                    f"\033[92m[INFO]:\033[97m Added to autostart: {exe_path}")

            elif action == "uninstall":
                try:
                    with winreg.OpenKey(key, REG_PATH, 0, winreg.KEY_WRITE) as regkey:
                        winreg.DeleteValue(regkey, APP_NAME)
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except FileNotFoundError:
                    print("\033[91m[ERROR]: Not found in autostart\033[0m")

        except PermissionError:
            print("\033[91m[ERROR]: Access denied. Run as administrator\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")
