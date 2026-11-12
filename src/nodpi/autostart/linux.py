"""Linux autostart via a systemd user service"""

import os
import subprocess
import sys

from pathlib import Path

from nodpi.interfaces import IAutostartManager

APP_NAME = "NoDPIProxy"

SERVICE_TEMPLATE = """[Unit]
Description=NoDPIProxy Service
After=network.target graphical-session.target
Wants=network.target

[Service]
Type=simple
ExecStart={exec_path} --blacklist "{blacklist_path}" --quiet
Restart=on-failure
RestartSec=5
Environment=DISPLAY=:0
Environment=XAUTHORITY=%h/.Xauthority

[Install]
WantedBy=default.target
"""


class LinuxAutostartManager(IAutostartManager):
    """Manages Linux autostart using systemd user services"""

    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        """Manages Linux autostart using systemd user services"""

        exec_path = sys.executable
        service_name = f"{APP_NAME.lower()}.service"

        user_service_dir = Path.home() / ".config" / "systemd" / "user"
        service_file = user_service_dir / service_name

        blacklist_path = f"{os.path.dirname(exec_path)}/blacklist.txt"

        if action == "install":
            try:
                user_service_dir.mkdir(parents=True, exist_ok=True)

                with open(service_file, "w", encoding="utf-8") as f:
                    f.write(SERVICE_TEMPLATE.format(
                        exec_path=exec_path, blacklist_path=blacklist_path))

                subprocess.run(
                    ["systemctl", "--user", "daemon-reload"], check=True)
                subprocess.run(
                    ["systemctl", "--user", "enable", service_name], check=True
                )
                subprocess.run(
                    ["systemctl", "--user", "start", service_name], check=True
                )

                print(
                    f"\033[92m[INFO]:\033[97m Service installed and started: {service_name}"
                )
                print("\033[93m[NOTE]:\033[97m Service will auto-start on login")

            except subprocess.CalledProcessError as e:
                print(f"\033[91m[ERROR]: Systemd command failed: {e}\033[0m")
            except Exception as e:
                print(
                    f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")

        elif action == "uninstall":
            try:
                subprocess.run(
                    ["systemctl", "--user", "stop", service_name],
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    ["systemctl", "--user", "disable", service_name],
                    capture_output=True,
                    check=True,
                )

                if service_file.exists():
                    service_file.unlink()

                subprocess.run(
                    ["systemctl", "--user", "daemon-reload"], check=True)

                print("\033[92m[INFO]:\033[97m Service removed from autostart")

            except subprocess.CalledProcessError as e:
                print(f"\033[91m[ERROR]: Systemd command failed: {e}\033[0m")
            except Exception as e:
                print(
                    f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")
