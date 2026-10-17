"""Open the MT5 Order window and place a Buy Limit — pure ctypes.

Run on Windows with MetaTrader 5 already running:

    python examples/open_buy_limit.py EURUSD 0.10 1.08500
"""

import sys

from mt5auto import MT5Terminal, ids


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    symbol, volume, price = sys.argv[1], sys.argv[2], sys.argv[3]

    t = MT5Terminal.find()
    print(f"attached: {t!r}")

    # Open Order window the same way the F9 accelerator does.
    t.open_new_order()
    win = t.find_order_window(timeout=8.0)
    print(f"order window: hwnd={win.hwnd:#x} title={win.title!r} class={win.class_name!r}")

    # Inspect which stable controls are present.
    controls = t.child_controls(win.hwnd)
    for cid, hwnd in sorted(controls.items()):
        print(f"  ctrl 0x{cid:04X} -> hwnd {hwnd:#x}")

    print("controls present:",
          "symbol-listbox" if ids.OrderControl.SYMBOL_LISTBOX in controls else "NO symbol listbox",
          "| volume-combo" if ids.OrderControl.VOLUME_COMBO in controls else "| NO volume combo")
    print(f"requested: {symbol} volume={volume} price={price} (type=Buy Limit 0x{ids.Command.BUY_LIMIT:04X})")
    print("-> selecting the order type routes via the chart-context command id;")
    print("   fill symbol/price in the dialog, then confirm manually or via OrderWindow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
