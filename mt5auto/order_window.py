"""
mt5auto.order_window — drive the "Order" window (RT_DIALOG 2405).

What reverse engineering established about this window:

* The seven order-type selectors (Market / Buy Limit / Sell Limit / Buy Stop /
  Sell Stop / Buy StopLimit / Sell StopLimit) are BUTTON controls with ids
  0x2B6C..0x2B72, but they are *custom drawn and initially hidden* — MT5
  shows one of them depending on the selected type. Sending BM_CLICK to the
  hidden one is therefore unreliable; prefer ``select_type`` which combines
  the context-menu command ids (0x8155..0x8158) with a BM_CLICK fallback.
* The Buy/Sell execution buttons of the Order window are NOT resource
  controls — they are custom drawn by MT5 code. There is no stable control
  id for them; see RESEARCH.md. ``confirm`` uses the default IDOK path and
  is marked experimental.
* The One Click Trading checkbox (0x291A), Symbol listbox (0x28B9) and
  Volume combobox (0x285B) ARE standard controls with stable ids.
"""

from __future__ import annotations

import ctypes
import time

from . import ids
from . import winapi as _w
from .terminal import MT5Terminal, WindowHandle


class OrderWindow:
    """Wrapper around the MT5 Order dialog (resource id 2405)."""

    def __init__(self, terminal: MT5Terminal, hwnd: int):
        self.terminal = terminal
        self.hwnd = hwnd

    # ------------------------------------------------------------------
    # open / attach
    # ------------------------------------------------------------------
    @classmethod
    def open(cls, terminal: MT5Terminal, timeout: float = 5.0, title: str | None = None) -> "OrderWindow":
        """Send the New Order command and wait for the dialog."""
        terminal.open_new_order()
        win = terminal.find_order_window(timeout=timeout, title=title)
        return cls(terminal, win.hwnd)

    # ------------------------------------------------------------------
    # standard controls (stable ids from RT_DIALOG 2405)
    # ------------------------------------------------------------------
    def _send(self, ctrl_id: int, msg: int, wparam: int = 0, lparam: int = 0) -> int:
        return int(_w.user32.SendDlgItemMessageW(self.hwnd, ctrl_id, msg, wparam, lparam))

    def select_symbol(self, symbol: str) -> bool:
        """Select a symbol in the Symbol listbox (0x28B9). Returns success."""
        buf = ctypes.create_unicode_buffer(symbol)
        idx = self._send(ids.OrderControl.SYMBOL_LISTBOX, _w.LB_FINDSTRINGEXACT, -1,
                         ctypes.addressof(buf))
        if idx in (0xFFFFFFFF, -1):  # LB_ERR
            return False
        self._send(ids.OrderControl.SYMBOL_LISTBOX, _w.LB_SETCURSEL, idx, 0)
        return True

    def set_volume(self, volume: float | str) -> bool:
        """Set volume in the combobox (0x285B).

        The volume combo is editable; if the exact text is present we select
        it, otherwise we type it into the edit portion.
        """
        text = f"{volume:g}" if isinstance(volume, float) else str(volume)
        buf = ctypes.create_unicode_buffer(text)
        idx = self._send(ids.OrderControl.VOLUME_COMBO, _w.CB_FINDSTRINGEXACT, -1,
                         ctypes.addressof(buf))
        if idx not in (0xFFFFFFFF, -1):
            self._send(ids.OrderControl.VOLUME_COMBO, _w.CB_SETCURSEL, idx, 0)
            return True
        # Fallback: find the edit child of the combobox and set its text.
        edit = _w.user32.FindWindowExW(
            _w.user32.GetDlgItem(self.hwnd, ids.OrderControl.VOLUME_COMBO), 0, "Edit", None
        )
        if not edit:
            return False
        _w.user32.SetWindowTextW(edit, text)
        return True

    def set_one_click(self, checked: bool) -> None:
        """Toggle the "One Click Trading" checkbox (0x291A)."""
        self._send(ids.OrderControl.ONE_CLICK_CHECKBOX, _w.BM_SETCHECK,
                   _w.BST_CHECKED if checked else _w.BST_UNCHECKED, 0)

    def one_click_checked(self) -> bool:
        return bool(self._send(ids.OrderControl.ONE_CLICK_CHECKBOX, 0xF0, 0, 0))  # BM_GETCHECK

    # ------------------------------------------------------------------
    # order-type selection
    # ------------------------------------------------------------------
    def select_type(self, command: int | None = None) -> bool:
        """Select the order type.

        Preferred path: WM_COMMAND with the chart-context ids (they route
        through the same internal command tables as the UI):

            BUY_LIMIT 0x8155, BUY_STOP 0x8156,
            SELL_LIMIT 0x8157, SELL_STOP 0x8158

        Fallback: WM_COMMAND with the button control id 0x2B6C..0x2B72
        inside the dialog.
        """
        cmd_to_ctrl = {
            ids.Command.BUY_LIMIT: ids.OrderControl.ORDER_TYPE_BUY_LIMIT,
            ids.Command.BUY_STOP: ids.OrderControl.ORDER_TYPE_BUY_STOP,
            ids.Command.SELL_LIMIT: ids.OrderControl.ORDER_TYPE_SELL_LIMIT,
            ids.Command.SELL_STOP: ids.OrderControl.ORDER_TYPE_SELL_STOP,
        }
        if command in cmd_to_ctrl:
            self.terminal.send_command(command)
            return True
        if command in ids.OrderControl.ORDER_TYPE_BUTTONS:
            return bool(_w.user32.PostMessageW(self.hwnd, _w.WM_COMMAND, command, 0))
        return False

    def click_order_type_button(self, ctrl_id: int) -> None:
        """BM_CLICK one of the custom-drawn type buttons (experimental)."""
        if ctrl_id not in ids.OrderControl.ORDER_TYPE_BUTTONS:
            raise ValueError(f"{ctrl_id:#x} is not an order-type button id")
        _w.user32.SendDlgItemMessageW(self.hwnd, ctrl_id, _w.BM_CLICK, 0, 0)

    # ------------------------------------------------------------------
    # execution (experimental — Buy/Sell are custom drawn, no control id)
    # ------------------------------------------------------------------
    def confirm(self) -> None:
        """Post the default action (IDOK) to the dialog."""
        _w.user32.PostMessageW(self.hwnd, _w.WM_COMMAND, 1, 0)  # IDOK

    def cancel(self) -> None:
        _w.user32.PostMessageW(self.hwnd, _w.WM_COMMAND, 2, 0)  # IDCANCEL

    def close(self) -> None:
        self.cancel()

    def wait_closed(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not _w.user32.IsWindow(self.hwnd):
                return True
            time.sleep(0.1)
        return not bool(_w.user32.IsWindow(self.hwnd))


def from_handle(terminal: MT5Terminal, win: WindowHandle) -> OrderWindow:
    return OrderWindow(terminal, win.hwnd)
