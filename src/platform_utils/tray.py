
import os
import sys
import time
import threading

from typing import Optional

if sys.platform != "win32":
    raise OSError("Tray is only supported on Windows")

import ctypes
import ctypes.wintypes

# WinAPI constants
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 1
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WM_SYSCOMMAND = 0x0112
SC_MINIMIZE = 0xF020
NIM_ADD = 0x00000000
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
SW_HIDE = 0
SW_RESTORE = 9
MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
TPM_LEFTALIGN = 0x0000
GWL_WNDPROC = -4
IDI_APPLICATION = ctypes.cast(32512, ctypes.wintypes.LPCWSTR)

ID_TRAY_SHOW = 1001
ID_TRAY_EXIT = 1002

ctypes.windll.user32.DefWindowProcW.restype = ctypes.c_long
ctypes.windll.user32.DefWindowProcW.argtypes = [
    ctypes.wintypes.HWND,
    ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
]
ctypes.windll.user32.CallWindowProcW.restype = ctypes.c_long
ctypes.windll.user32.CallWindowProcW.argtypes = [
    ctypes.c_void_p,
    ctypes.wintypes.HWND,
    ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
]
ctypes.windll.user32.SetWindowLongPtrW.restype = ctypes.c_void_p
ctypes.windll.user32.SetWindowLongPtrW.argtypes = [
    ctypes.wintypes.HWND,
    ctypes.c_int,
    ctypes.c_void_p,
]
ctypes.windll.user32.GetWindowLongPtrW.restype = ctypes.c_void_p
ctypes.windll.user32.GetWindowLongPtrW.argtypes = [
    ctypes.wintypes.HWND,
    ctypes.c_int,
]
ctypes.windll.user32.AppendMenuW.restype = ctypes.wintypes.BOOL
ctypes.windll.user32.AppendMenuW.argtypes = [
    ctypes.wintypes.HMENU,
    ctypes.wintypes.UINT,
    ctypes.c_ulong,
    ctypes.wintypes.LPCWSTR,
]

WNDPROCTYPE = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.wintypes.HWND,
    ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.wintypes.DWORD),
        ("hWnd", ctypes.wintypes.HWND),
        ("uID", ctypes.wintypes.UINT),
        ("uFlags", ctypes.wintypes.UINT),
        ("uCallbackMessage", ctypes.wintypes.UINT),
        ("hIcon", ctypes.wintypes.HICON),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", ctypes.wintypes.DWORD),
        ("dwStateMask", ctypes.wintypes.DWORD),
        ("szInfo", ctypes.c_wchar * 256),
        ("uVersion", ctypes.wintypes.UINT),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", ctypes.wintypes.DWORD),
    ]


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.wintypes.UINT),
        ("lpfnWndProc", WNDPROCTYPE),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.wintypes.HINSTANCE),
        ("hIcon", ctypes.wintypes.HICON),
        ("hCursor", ctypes.wintypes.HANDLE),
        ("hbrBackground", ctypes.wintypes.HBRUSH),
        ("lpszMenuName", ctypes.wintypes.LPCWSTR),
        ("lpszClassName", ctypes.wintypes.LPCWSTR),
    ]


class WindowsTrayIcon:
    """Implements a Windows tray icon"""

    _CLASS_NAME = "NoDPITrayWnd"

    def __init__(self, tooltip: str = "NoDPI"):
        self.tooltip = tooltip
        self.hwnd: Optional[int] = None
        self.nid: Optional[NOTIFYICONDATA] = None
        self._console_hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        self._thread: Optional[threading.Thread] = None
        self._wnd_proc_ref = None
        self._orig_console_proc = None
        self._hooked_console_proc_ref = None

    def start(self) -> None:

        self._thread = threading.Thread(
            target=self._message_loop, daemon=True, name="TrayThread"
        )
        self._thread.start()
        time.sleep(0.3)
        self._install_minimize_hook()

    def hide_to_tray(self) -> None:
        ctypes.windll.user32.ShowWindow(self._console_hwnd, SW_HIDE)

    def show_from_tray(self) -> None:
        ctypes.windll.user32.ShowWindow(self._console_hwnd, SW_RESTORE)
        ctypes.windll.user32.SetForegroundWindow(self._console_hwnd)

    def _message_loop(self) -> None:
        self._create_tray_window()
        self._add_tray_icon()

        msg = ctypes.wintypes.MSG()
        while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

        self._remove_tray_icon()

    def _create_tray_window(self) -> None:
        hinstance = ctypes.windll.kernel32.GetModuleHandleW(None)

        def _wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_TRAYICON:
                if lparam == WM_LBUTTONDBLCLK:
                    self.show_from_tray()
                elif lparam == WM_RBUTTONUP:
                    self._show_context_menu(hwnd)
            elif msg == WM_COMMAND:
                cmd = wparam & 0xFFFF
                if cmd == ID_TRAY_SHOW:
                    self.show_from_tray()
                elif cmd == ID_TRAY_EXIT:
                    self._remove_tray_icon()
                    ctypes.windll.user32.PostQuitMessage(0)
                    os._exit(0)
            elif msg == WM_DESTROY:
                ctypes.windll.user32.PostQuitMessage(0)
                return 0
            return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wnd_proc_ref = WNDPROCTYPE(_wnd_proc)

        wc = WNDCLASS()
        wc.lpfnWndProc = self._wnd_proc_ref
        wc.hInstance = hinstance
        wc.lpszClassName = self._CLASS_NAME

        ctypes.windll.user32.RegisterClassW(ctypes.byref(wc))

        self.hwnd = ctypes.windll.user32.CreateWindowExW(
            0,
            self._CLASS_NAME,
            "NoDPI Tray",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            hinstance,
            None,
        )

    def _load_icon(self) -> int:

        if getattr(sys, "frozen", False):
            hinstance = ctypes.windll.kernel32.GetModuleHandleW(None)
            hicon = ctypes.windll.user32.LoadIconW(
                hinstance,
                ctypes.cast(1, ctypes.wintypes.LPCWSTR),
            )
            if hicon:
                return hicon

        exe_path = sys.executable
        if exe_path and os.path.isfile(exe_path):
            hicon_large = ctypes.wintypes.HICON(0)
            hicon_small = ctypes.wintypes.HICON(0)
            n = ctypes.windll.shell32.ExtractIconExW(
                ctypes.c_wchar_p(exe_path),
                0,
                ctypes.byref(hicon_large),
                ctypes.byref(hicon_small),
                1,
            )
            if n > 0:
                hicon = hicon_small.value or hicon_large.value
                if hicon:
                    return hicon

        return ctypes.windll.user32.LoadIconW(None, IDI_APPLICATION)

    def _add_tray_icon(self) -> None:
        hicon = self._load_icon()

        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = hicon
        nid.szTip = self.tooltip
        self.nid = nid

        ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

    def _remove_tray_icon(self) -> None:
        if self.nid:
            ctypes.windll.shell32.Shell_NotifyIconW(
                NIM_DELETE, ctypes.byref(self.nid))
            self.nid = None

    def _show_context_menu(self, hwnd: int) -> None:
        hmenu = ctypes.windll.user32.CreatePopupMenu()

        ctypes.windll.user32.AppendMenuW(
            hmenu, MF_STRING, ID_TRAY_SHOW, ctypes.c_wchar_p("Show")
        )
        ctypes.windll.user32.AppendMenuW(
            hmenu, MF_SEPARATOR, 0, ctypes.c_wchar_p(None))
        ctypes.windll.user32.AppendMenuW(
            hmenu, MF_STRING, ID_TRAY_EXIT, ctypes.c_wchar_p("Exit")
        )

        pt = ctypes.wintypes.POINT()
        ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
        ctypes.windll.user32.SetForegroundWindow(hwnd)
        ctypes.windll.user32.TrackPopupMenu(
            hmenu, TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, None
        )
        ctypes.windll.user32.PostMessageW(hwnd, 0, 0, 0)
        ctypes.windll.user32.DestroyMenu(hmenu)

    def _install_minimize_hook(self) -> None:

        if not self._console_hwnd:
            return

        orig = ctypes.windll.user32.GetWindowLongPtrW(
            self._console_hwnd, GWL_WNDPROC)

        if orig is None or orig == 0:
            self._start_minimize_polling()
            return

        def _hooked(hwnd, msg, wparam, lparam):
            if msg == WM_SYSCOMMAND and (wparam & 0xFFF0) == SC_MINIMIZE:
                self.hide_to_tray()
                return 0
            return ctypes.windll.user32.CallWindowProcW(
                self._orig_console_proc, hwnd, msg, wparam, lparam
            )

        self._hooked_console_proc_ref = WNDPROCTYPE(_hooked)
        self._orig_console_proc = orig

        ctypes.windll.user32.SetWindowLongPtrW(
            self._console_hwnd, GWL_WNDPROC, self._hooked_console_proc_ref
        )

    def _start_minimize_polling(self) -> None:

        SW_SHOWMINIMIZED = 2

        class WINDOWPLACEMENT(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.wintypes.UINT),
                ("flags", ctypes.wintypes.UINT),
                ("showCmd", ctypes.wintypes.UINT),
                ("ptMinPosition", ctypes.wintypes.POINT),
                ("ptMaxPosition", ctypes.wintypes.POINT),
                ("rcNormalPosition", ctypes.wintypes.RECT),
            ]

        def _poll():
            wp = WINDOWPLACEMENT()
            wp.length = ctypes.sizeof(WINDOWPLACEMENT)
            hwnd = self._console_hwnd
            while True:
                time.sleep(0.2)
                ctypes.windll.user32.GetWindowPlacement(hwnd, ctypes.byref(wp))
                if wp.showCmd == SW_SHOWMINIMIZED:
                    self.hide_to_tray()

        t = threading.Thread(target=_poll, daemon=True, name="TrayPollThread")
        t.start()
