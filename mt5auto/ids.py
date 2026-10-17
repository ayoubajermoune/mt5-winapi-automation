"""
mt5auto.ids — stable identifiers extracted from terminal64.exe (PE32+, SHA-256
481dad458e5e2c05188514eb803b3ca4ffa29fd83bfcf2b0e985a87666a4a224).

All values below come from static reverse engineering of MetaTrader 5
resources (RT_MENU / RT_ACCELERATOR / RT_DIALOG / RT_STRING) and from the
WM_COMMAND dispatch tables found in .rdata. They are *build-specific*:
pin your library to the SHA-256 above and re-extract after an MT5 update.

Reference: see RESEARCH.md for the full evidence chain.
"""

# ---------------------------------------------------------------------------
# WM_COMMAND ids — main window dispatch table (0x1423bf000 region, 370 entries)
# Entry layout observed: [handler:8][0x111=WM_COMMAND:8][cmd:4][cmd:4][0x3a:8]
# ---------------------------------------------------------------------------

WM_COMMAND = 0x0111

class Command:
    """Menu / accelerator command ids routed through WM_COMMAND."""

    # --- main window (table at 0x1423bfce0..0x1423c0940) ---
    NEW_ORDER = 0x8050            # "&New Order\tF9" -> handler 0x140bc6a90
    OPTIONS_CTRL_O = 0x8051       # Ctrl+O
    F4 = 0x8052                   # F4
    CTRL_E = 0x8053               # Ctrl+E
    MARKET_WATCH = 0x804B         # Ctrl+M
    TOOLBOX = 0x8049              # Ctrl+T
    F11 = 0x804F
    POPUP_PRICES = 0x8146         # F10

    # --- chart context menu (table at 0x141df8f38..) ---
    ONE_CLICK_TRADING = 0x838F    # Alt+T, handler 0x140a64110
    CHART_CTX_NEW_ORDER = 0x8154  # handler 0x140a6d5b0
    BUY_LIMIT = 0x8155            # handler 0x140a54d50
    BUY_STOP = 0x8156             # handler 0x140a6d130
    SELL_LIMIT = 0x8157           # handler 0x140a6d240
    SELL_STOP = 0x8158            # handler 0x140a6d350
    STOP_LOSS_CTX = 0x8159
    TAKE_PROFIT_CTX = 0x815A

    # --- other surfaces ---
    CHART_TAB_NEW_ORDER = 0x8003  # chart tab bar,   handler 0x140e9df70
    MARKET_WATCH_CTX_NEW_ORDER = 0x811A   # handler 0x1412703e0
    NAVIGATOR_BUY_FROM_MARKET = 0x8129    # handler 0x1412a9560

    # --- trade tab context menu (table at 0x1424501e8..) ---
    TRADE_CTX_NEW_ORDER = 0x8105  # handler 0x140fa7a80
    MODIFY_OR_DELETE = 0x8104     # handler 0x140fa7d10
    CLOSE_POSITION = 0x8109       # handler 0x140fa7ae0
    CLOSE_ALL = 0x9910            # handler 0x140fa9f20
    DELETE_ALL_ORDERS = 0x9913

    # --- depth of market context ---
    DOM_BUY_LIMIT = 0x839B
    DOM_SELL_LIMIT = 0x839C
    DOM_BUY_STOP = 0x839D
    DOM_SELL_STOP = 0x839E
    DOM_STOP_LOSS = 0x839F
    DOM_TAKE_PROFIT = 0x83A0
    DOM_MODIFY = 0x83A4
    DOM_DELETE = 0x83A5

    # --- toolbox tabs ---
    TOOLBOX_NEW_ORDER_MAILBOX = 0x9906
    TOOLBOX_NEW_ORDER_ALERTS = 0x9904
    TOOLBOX_NEW_ORDER_JOURNAL = 0x9905
    TOOLBOX_NEW_ORDER_EXPERTS = 0x9907


# ---------------------------------------------------------------------------
# Internal (undocumented) MT5 message: sent by the command-routing helper at
# 0x140ee18e0 as  SendMessage(hwnd, 0x419, cmd_id, 0)  where hwnd lives at
# [view_object+0x40]. State is stored at [obj+0x1dc], then a 500 ms timer and
# an (hwnd, 0, 1) call follow (likely InvalidateRect).
# ---------------------------------------------------------------------------
MT5_INTERNAL_CMD_MSG = 0x419


# ---------------------------------------------------------------------------
# "Order" dialog (RT_DIALOG id 2405 = 0x965, template loaded by 0x1404ed4e0).
# 19 controls; the seven order-type buttons are custom-drawn (no text,
# style 0x40000002 = WS_CHILD|WS_VISIBLE is NOT set — they start hidden and
# are shown/painted by MT5 code).
# ---------------------------------------------------------------------------
DIALOG_ORDER = 2405  # 0x965

class OrderControl:
    """Control ids inside the "Order" dialog (RT_DIALOG 2405)."""

    # 7 custom-drawn order-type buttons: Market / BuyLimit / SellLimit /
    # BuyStop / SellStop / BuyStopLimit / SellStopLimit
    ORDER_TYPE_MARKET = 0x2B6C
    ORDER_TYPE_BUY_LIMIT = 0x2B6D
    ORDER_TYPE_SELL_LIMIT = 0x2B6E
    ORDER_TYPE_BUY_STOP = 0x2B6F
    ORDER_TYPE_SELL_STOP = 0x2B70
    ORDER_TYPE_BUY_STOP_LIMIT = 0x2B71
    ORDER_TYPE_SELL_STOP_LIMIT = 0x2B72
    ORDER_TYPE_BUTTONS = tuple(range(0x2B6C, 0x2B73))

    ONE_CLICK_CHECKBOX = 0x291A   # BUTTON "One Click Trading"
    TICK_CHART = 0x2B7B
    DEPTH_OF_MARKET_BTN = 0x2B7C
    MINIMIZE_BTN = 0x2B85

    SYMBOL_LISTBOX = 0x28B9       # LISTBOX "Symbol:"
    VOLUME_COMBO = 0x285B         # COMBOBOX (volume)
    CONTROL_2859 = 0x2859
    CONTROL_27B8 = 0x27B8
    CONTROL_2B45 = 0x2B45
    TRADE_LIST_VIEW = 0x29C7      # SysListView32
    CONTROL_2723 = 0x2723
    RISK_WARNING_STATIC = 0x29E1  # STATIC, text contains %s


# "One Click Trading" terms dialog (RT_DIALOG 578) shown the first time.
DIALOG_ONE_CLICK_TERMS = 578

class OneClickTermsControl:
    ACCEPT_BUTTON = 1
    CANCEL_BUTTON = 2
    TERMS_EDIT = 0x291B
    TERMS_LISTBOX = 0x2781


# ---------------------------------------------------------------------------
# Window discovery hints (observed, not fully verified for every MT5 build).
# MT5 registers standard-looking classes; discovery in terminal.py falls back
# to EnumWindows + process name when class names differ.
# ---------------------------------------------------------------------------
# Window discovery hints.
# MAIN_WINDOW_CLASS "Terminal": verified twice — (a) statically, Ghidra exact
#   NUL-terminated UTF-16 string at .rdata 0x14287c584 (5 copies); (b) live
#   under Wine/X11 (xdotool class match on the running terminal64.exe).
# CHART_WINDOW_CLASS: UNKNOWN — an earlier guess ("ChartsFrame") has ZERO
#   occurrences in the binary (verified with Ghidra string scan). Chart
#   windows are found as child windows of the main frame instead.
MAIN_WINDOW_CLASS = "Terminal"
ORDER_WINDOW_TITLE = "Order"         # matched as substring; real title is
                                     # "Order: EURUSD - Euro vs US Dollar" (locale-dependent)
CHART_WINDOW_CLASS = None            # not statically resolvable (encrypted .cod* code)
ONE_CLICK_PANEL_CLASS = None         # custom-drawn: no stable class found

# Executable name used for process-based discovery.
TERMINAL_PROCESS_NAME = "terminal64.exe"

# Build this library was extracted from:
TERMINAL_SHA256 = "481dad458e5e2c05188514eb803b3ca4ffa29fd83bfcf2b0e985a87666a4a224"
