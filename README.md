# mt5-winapi

Stable Win32 automation for **MetaTrader 5** (`terminal64.exe`) built on
`ctypes`, with an optional `pywinauto` adapter.

Instead of screen scraping, this library drives the terminal through the
**WM_COMMAND ids and dialog control ids extracted by reverse engineering** the
binary's own resources and dispatch tables.

> ⚠️ **Build-specific**: all identifiers were extracted from one MT5 build
> (SHA-256 `481dad45…6a4a224`). Re-extract them after every MT5 update —
> see [RESEARCH.md](RESEARCH.md).

## Install

```bash
pip install .                # zero dependencies (ctypes only)
pip install '.[pywinauto]'   # with the pywinauto adapter
```

Windows only for runtime; the `mt5auto.ids` table imports anywhere
(useful for tests and tooling).

## Quick start

```python
from mt5auto import MT5Terminal, ids

t = MT5Terminal.find()        # attaches to the running terminal64.exe
t.open_new_order()            # == menu "New Order" / F9  (WM_COMMAND 0x8050)
t.toggle_one_click_trading()  # == Alt+T                  (WM_COMMAND 0x838F)
t.close_all_positions()       # == Trade tab "Close All"  (WM_COMMAND 0x9910)
```

### Order window

```python
from mt5auto import OrderWindow

dlg = OrderWindow.open(t)                    # sends 0x8050, waits for dialog 2405
dlg.select_symbol("EURUSD")                  # LISTBOX 0x28B9
dlg.set_volume(0.10)                         # COMBOBOX 0x285B
dlg.select_type(ids.Command.BUY_LIMIT)       # routes 0x8155
dlg.confirm()                                # IDOK
```

### pywinauto (optional)

```python
from mt5auto.pywinauto_adapter import PywinautoOrderWindow

dlg = PywinautoOrderWindow.attach()
dlg.select_symbol("EURUSD")
dlg.set_volume("0.10")
```

## What is stable and what is not

| Stable (resource-derived) | Not stable |
|---|---|
| Command ids `0x8050…0x9913` (RT_MENU / RT_ACCELERATOR / dispatch tables) | Function addresses (change every build) |
| Dialog id 2405 + control ids `0x2723…0x2B85` (RT_DIALOG) | Window class names (partly in encrypted sections) |
| Internal command message `0x419` (WM_USER range) | One-click SELL/BUY buttons — **custom drawn, no control id**; only coordinate-based `SendInput` (fragile) |
| Process-based window discovery (`terminal64.exe`) | Title-based discovery (locale-dependent) |

The seven order-type buttons in the Order dialog (`0x2B6C…0x2B72`) exist as
BUTTON controls but are **custom drawn and initially hidden** — prefer the
command-id path (`0x8155…0x8158`) over `BM_CLICK`.

## Layout

```
mt5auto/
  ids.py              # extracted command/dialog/control ids (+ provenance)
  winapi.py           # ctypes bindings (user32/kernel32)
  terminal.py         # MT5Terminal: discovery + WM_COMMAND dispatch
  order_window.py     # Order dialog (RT_DIALOG 2405) helpers
  chart.py            # chart windows + one-click panel (coordinate-based)
  pywinauto_adapter.py
examples/             # runnable scripts
tests/                # identifier-table tests (run anywhere)
tools/extract_ids.py  # re-extract & verify ids against any MT5 build
data/                 # full WM_COMMAND dispatch-table dump (370 entries)
RESEARCH.md           # full reverse-engineering evidence chain
```

## Re-extracting after an MT5 update

```bash
python tools/extract_ids.py "C:\Program Files\MetaTrader 5\terminal64.exe"
```

Exit 0 = the pinned ids still match that build; exit 1 = drift detected
(the report lists exactly which identifiers moved).

## Tests

```bash
python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Automating a trading terminal may violate your broker's terms of service.
Use at your own risk; this project is for research and testing purposes.
