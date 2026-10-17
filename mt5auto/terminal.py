"""
mt5auto.terminal — high-level facade: locate a running MetaTrader 5 terminal
and drive it through the stable WM_COMMAND ids extracted by reverse
engineering (see ids.py / RESEARCH.md).

Typical use::

    from mt5auto import MT5Terminal

    t = MT5Terminal.find()          # attaches to the running terminal64.exe
    t.open_new_order()              # same as menu "New Order" / F9
    t.toggle_one_click_trading()    # same as Alt+T on a chart
    t.close_all_positions()         # Trade tab "Close All"
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import ids
from . import winapi as _w
from .winapi import WM_COMMAND


@dataclass(frozen=True)
class WindowHandle:
    hwnd: int
    title: str
    class_name: str
    pid: int
    process: str


class MT5Terminal:
    """Attachment to one running MetaTrader 5 terminal instance."""

    def __init__(self, main: WindowHandle):
        self.main = main

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    @classmethod
    def find(cls, process_name: str | None = None) -> "MT5Terminal":
        """Find the main window of a running MT5 terminal.

        Discovery is process-based (terminal64.exe by default) — class and
        window titles change between builds/locales, process names do not.
        """
        target = (process_name or ids.TERMINAL_PROCESS_NAME).lower()
        found: list[WindowHandle] = []

        def _cb(hwnd):
            if _w.user32.IsWindowVisible(hwnd) and _w.user32.GetParent(hwnd) == 0:
                pid = _w.pid_of(hwnd)
                if pid and _w.process_name(pid) == target:
                    found.append(WindowHandle(
                        hwnd=hwnd,
                        title=_w.window_text(hwnd),
                        class_name=_w.window_class(hwnd),
                        pid=pid,
                        process=target,
                    ))
            return True

        _w.enum_windows(_cb)
        if not found:
            raise LookupError(
                f"no visible top-level window of {target!r} found — "
                "is the terminal running?"
            )
        # Prefer the largest-titled main frame (MT5 can open several).
        found.sort(key=lambda w: len(w.title), reverse=True)
        return cls(found[0])

    # ------------------------------------------------------------------
    # Low-level message plumbing
    # ------------------------------------------------------------------
    def send_command(self, command: int, *, async_: bool = True) -> None:
        """Send a WM_COMMAND with the given command id to the main window.

        async_=True uses PostMessageW (non-blocking, like a real menu click);
        async_=False uses SendMessageW (blocks until handled).
        """
        fn = _w.user32.PostMessageW if async_ else _w.user32.SendMessageW
        fn(self.main.hwnd, WM_COMMAND, command, 0)

    def send_internal(self, command: int, *, async_: bool = False) -> None:
        """Send MT5's undocumented internal command message 0x419.

        This is the message the in-app command router (helper at 0x140ee18e0)
        uses internally with wParam = command id, lParam = 0.
        """
        fn = _w.user32.PostMessageW if async_ else _w.user32.SendMessageW
        fn(self.main.hwnd, ids.MT5_INTERNAL_CMD_MSG, command, 0)

    # ------------------------------------------------------------------
    # Commands (menu-equivalents; stable for the analyzed build)
    # ------------------------------------------------------------------
    def open_new_order(self) -> None:
        """Open the Order window (menu: New Order / F9)."""
        self.send_command(ids.Command.NEW_ORDER)

    def toggle_one_click_trading(self) -> None:
        """Toggle One Click Trading panel (Alt+T on a chart)."""
        self.send_command(ids.Command.ONE_CLICK_TRADING)

    def open_market_watch(self) -> None:
        self.send_command(ids.Command.MARKET_WATCH)

    def open_toolbox(self) -> None:
        self.send_command(ids.Command.TOOLBOX)

    def open_popup_prices(self) -> None:
        self.send_command(ids.Command.POPUP_PRICES)

    def close_all_positions(self) -> None:
        """Trade tab context: Close All (0x9910)."""
        self.send_command(ids.Command.CLOSE_ALL)

    def delete_all_orders(self) -> None:
        self.send_command(ids.Command.DELETE_ALL_ORDERS)

    # ------------------------------------------------------------------
    # Order window
    # ------------------------------------------------------------------
    def find_order_window(self, timeout: float = 5.0, title: str | None = None) -> WindowHandle:
        """Wait for the Order window owned by this terminal and return it.

        The Order window is the dialog built from RT_DIALOG 2405. Its title
        is locale-dependent ("Order" in English) — pass ``title=`` otherwise.
        """
        wanted_title = (title or ids.ORDER_WINDOW_TITLE).lower()
        deadline = time.monotonic() + timeout
        while True:
            hit = self._find_owned_window(wanted_title)
            if hit is not None:
                return hit
            if time.monotonic() > deadline:
                raise LookupError(
                    f"Order window (dialog {ids.DIALOG_ORDER}) not found within {timeout}s"
                )
            time.sleep(0.15)

    def _find_owned_window(self, title_lower: str) -> WindowHandle | None:
        found: list[WindowHandle] = []

        def _cb(hwnd):
            if not _w.user32.IsWindowVisible(hwnd):
                return True
            if _w.pid_of(hwnd) != self.main.pid:
                return True
            if title_lower in _w.window_text(hwnd).lower():
                found.append(WindowHandle(
                    hwnd=hwnd,
                    title=_w.window_text(hwnd),
                    class_name=_w.window_class(hwnd),
                    pid=self.main.pid,
                    process=self.main.process,
                ))
            return True

        _w.enum_windows(_cb)
        return found[0] if found else None

    def child_controls(self, hwnd: int) -> dict[int, int]:
        """Map control-id -> hwnd for all children of a dialog."""
        mapping: dict[int, int] = {}

        def _cb(child):
            cid = _w.user32.GetDlgCtrlID(child)
            if cid:
                mapping[cid] = child
            return True

        _w.enum_child_windows(hwnd, _cb)
        return mapping

    def activate(self) -> None:
        """Bring the terminal to the foreground (restoring if minimized)."""
        h = self.main.hwnd
        if _w.user32.IsIconic(h):
            _w.user32.ShowWindow(h, _w.SW_RESTORE)
        _w.user32.SetForegroundWindow(h)

    def __repr__(self) -> str:  # pragma: no cover
        return (f"<MT5Terminal hwnd={self.main.hwnd:#x} pid={self.main.pid} "
                f"title={self.main.title!r}>")
