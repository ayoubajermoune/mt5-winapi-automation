"""
mt5auto.pywinauto_adapter — optional pywinauto integration.

pywinauto is only imported when this module is used, so the core library
keeps a pure-ctypes, zero-dependency footprint.

The adapter is useful for inspection (control discovery, verification) and
for dialogs where pywinauto's control handling is more convenient. Command
dispatch itself should stay with :class:`mt5auto.terminal.MT5Terminal`,
because MT5's order buttons are custom drawn and not visible to
UI-Automation in a reliable way.
"""

from __future__ import annotations

from . import ids
from .terminal import MT5Terminal

try:
    from pywinauto import Application  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "mt5auto.pywinauto_adapter requires pywinauto: "
        "pip install 'mt5-winapi[pywinauto]'"
    ) from exc


class PywinautoOrderWindow:
    """Order dialog (RT_DIALOG 2405) via pywinauto, using stable control ids."""

    def __init__(self, app: Application, dialog):
        self.app = app
        self.dialog = dialog

    @classmethod
    def attach(cls, process: int | None = None, timeout: float = 10.0) -> "PywinautoOrderWindow":
        """Attach to the running terminal and wait for the Order dialog."""
        app = Application(backend="win32").connect(process=process) if process \
            else Application(backend="win32").connect(path=ids.TERMINAL_PROCESS_NAME)
        dlg = app.window(title_re=f".*{ids.ORDER_WINDOW_TITLE}.*")
        dlg.wait("exists visible", timeout=timeout)
        return cls(app, dlg)

    # Control access by the stable resource ids -------------------------
    def symbol_listbox(self):
        return self.dialog.child_window(auto_id=ids.OrderControl.SYMBOL_LISTBOX, class_name="ListBox")

    def volume_combo(self):
        return self.dialog.child_window(auto_id=ids.OrderControl.VOLUME_COMBO, class_name="ComboBox")

    def one_click_checkbox(self):
        return self.dialog.child_window(auto_id=ids.OrderControl.ONE_CLICK_CHECKBOX, class_name="Button")

    # Convenience -------------------------------------------------------
    def select_symbol(self, symbol: str) -> None:
        self.symbol_listbox().select(symbol)

    def set_volume(self, volume: str) -> None:
        self.volume_combo().set_edit_text(volume)

    def enable_one_click(self) -> None:
        self.one_click_checkbox().check()

    def cancel(self) -> None:
        self.dialog.close()
