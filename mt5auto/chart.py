"""
mt5auto.chart — chart-window helpers and the One Click Trading panel.

Findings from reverse engineering (see RESEARCH.md):

* The One Click Trading panel's SELL/BUY buttons are custom drawn directly
  on the chart window. They have **no resource control ids**, no stable
  window class, and are not reachable with GetDlgItem. Mouse injection
  (SendInput) at the panel's screen coordinates is the only stable-ish
  mechanism, and coordinates depend on chart geometry — treat as fragile.
* What IS stable: the Alt+T toggle (command 0x838F) and the internal
  command message 0x419. Both are exposed here.

"""

from __future__ import annotations

import ctypes
import time
from dataclasses import dataclass
from ctypes import wintypes as _wt

from . import ids
from . import winapi as _w
from .terminal import MT5Terminal

# INPUT structures for SendInput (mouse injection)
INPUT_MOUSE = 0
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

wintypes_RECT = _wt.RECT
_w.user32.GetWindowRect.argtypes = [_wt.HWND, ctypes.POINTER(_wt.RECT)]
_w.user32.GetWindowRect.restype = _wt.BOOL
_w.user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
_w.user32.SetCursorPos.restype = _wt.BOOL


@dataclass(frozen=True)
class Point:
    x: int
    y: int


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("mi", MOUSEINPUT)]


# SendInput signature (needs the INPUT structure defined above)
_w.user32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]
_w.user32.SendInput.restype = ctypes.c_uint


def _click_at(x: int, y: int) -> None:
    """Send a left click at screen coordinates via SendInput."""
    _w.user32.SetCursorPos(x, y)
    inp = INPUT(type=INPUT_MOUSE,
                mi=MOUSEINPUT(dx=0, dy=0, mouseData=0,
                              dwFlags=MOUSEEVENTF_LEFTDOWN, time=0, dwExtraInfo=None))
    _w.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))
    inp.mi.dwFlags = MOUSEEVENTF_LEFTUP
    _w.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))


class ChartWindow:
    """A single chart window of the terminal."""

    def __init__(self, terminal: MT5Terminal, hwnd: int):
        self.terminal = terminal
        self.hwnd = hwnd

    @classmethod
    def find_all(cls, terminal: MT5Terminal) -> list["ChartWindow"]:
        """Enumerate chart windows of this terminal by class name."""
        found: list[ChartWindow] = []

        def _cb(hwnd):
            if _w.pid_of(hwnd) == terminal.main.pid and \
                    _w.window_class(hwnd) == ids.CHART_WINDOW_CLASS:
                found.append(cls(terminal, hwnd))
            return True

        _w.enum_windows(_cb)
        return found

    def toggle_one_click_trading(self) -> None:
        """Alt+T equivalent for this chart (command 0x838F)."""
        # The command routes through the chart's own dispatch table; posting
        # to the main window reaches the same internal handler (0x140a64110).
        self.terminal.send_command(ids.Command.ONE_CLICK_TRADING)

    def rect(self) -> tuple[int, int, int, int]:
        """(left, top, right, bottom) in screen coordinates."""
        r = wintypes_RECT()
        _w.user32.GetWindowRect(self.hwnd, ctypes.byref(r))
        return r.left, r.top, r.right, r.bottom

    # ------------------------------------------------------------------
    # One Click Trading panel — FRAGILE, coordinates only
    # ------------------------------------------------------------------
    def one_click_buy_xy(self) -> Point:
        """Approximate screen point of the BUY button of the one-click panel.

        The panel sits at the top-right of the chart: BUY occupies the right
        half of a ~150px wide strip. Verify visually before production use.
        """
        _l, top, right, _b = self.rect()
        return Point(right - 30, top + 30)

    def one_click_sell_xy(self) -> Point:
        """Approximate screen point of the SELL button of the one-click panel."""
        _l, top, right, _b = self.rect()
        return Point(right - 120, top + 30)

    def click_one_click_buy(self, verify: bool = True) -> None:
        pt = self.one_click_buy_xy()
        if verify:
            self.terminal.activate()
            time.sleep(0.2)
        _click_at(pt.x, pt.y)

    def click_one_click_sell(self, verify: bool = True) -> None:
        pt = self.one_click_sell_xy()
        if verify:
            self.terminal.activate()
            time.sleep(0.2)
        _click_at(pt.x, pt.y)
