"""
mt5-winapi — stable Win32 automation for MetaTrader 5 (terminal64.exe).

Command ids, dialog ids and control ids in :mod:`mt5auto.ids` were extracted
by reverse engineering a specific MT5 build (see RESEARCH.md for the SHA-256
and the evidence chain). :mod:`mt5auto.ids` is importable on any OS; the
Win32 modules require Windows.
"""

from . import ids

__version__ = "0.1.0"
__all__ = ["ids", "MT5Terminal", "OrderWindow", "ChartWindow"]

try:
    from .terminal import MT5Terminal
    from .order_window import OrderWindow
    from .chart import ChartWindow
except ImportError:  # non-Windows: only ids are available
    MT5Terminal = None  # type: ignore
    OrderWindow = None  # type: ignore
    ChartWindow = None  # type: ignore
