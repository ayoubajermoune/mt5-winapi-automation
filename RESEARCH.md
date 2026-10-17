# RESEARCH — evidence chain

This document records how every identifier in `mt5auto/ids.py` was obtained,
so it can be re-extracted after an MT5 update.

## Target

| | |
|---|---|
| File | `MetaTrader 5/terminal64.exe` (Wine prefix copy) |
| Format | PE32+ GUI x86-64, 121,055,472 bytes, 12 sections |
| Image base | `0x140000000` |
| SHA-256 | `481dad458e5e2c05188514eb803b3ca4ffa29fd83bfcf2b0e985a87666a4a224` |
| Tools | REA 6.5.0 + Ghidra 12.1.4 (CLI fallback), objdump, custom PE-resource parsers (Python) |

> Methodology note: results from objdump and the custom resource parsers are
> **ordinary-tool observations**; Ghidra-derived results are REA Evidence.
> Both are labeled below.

## 1. Resources (ordinary-tool observation)

Custom DIALOGEX/ACCEL/MENU parsers were written. Key extractions:

- **RT_MENU / RT_ACCELERATOR**: main menu `&New Order\tF9` → **0x8050**;
  accelerator table 128 confirms **F9 → 0x8050**. Chart table 131:
  Alt+T → 0x838F (One Click Trading).
- **RT_DIALOG 2405 "Order"** (19 controls): seven BUTTON controls
  **0x2B6C–0x2B72**, custom-drawn, style `0x40000002`; One Click checkbox
  **0x291A**; symbol LISTBOX **0x28B9**; volume COMBOBOX **0x285B**.
- **RT_DIALOG 578**: One Click Trading terms (buttons id 1/2).
- No resource contains visible Buy/Sell execution buttons → MT5 custom
  draws them (confirmed by RT_STRING 0x0103 "Buy" / 0x0105 "Sell" being
  drawn strings, not control captions).

## 2. WM_COMMAND dispatch tables (ordinary-tool observation)

Rather than a monolithic WndProc switch, MT5 registers handlers in tables of
32-byte entries:

```
[handler VA:8][0x111 (WM_COMMAND):8][cmd:4][cmd:4][0x3a:8]
```

- **370 entries** in the main-window table (`.rdata` region
  `0x1423bf000–0x1423c1000`); full dump: `data/wm-command-table.txt`.
- Per-surface tables also found: chart context (`0x141df8f38+`), trade tab
  (`0x1424501e8+`), Market Watch (`0x14247f218+`).

Confirmed handler mapping (excerpt):

| cmd | surface | handler |
|---|---|---|
| 0x8050 New Order | main (F9) | `0x140bc6a90` |
| 0x8003 New Order | chart tab | `0x140e9df70` → `0x1410ac410` |
| 0x8154 New Order | chart ctx | `0x140a6d5b0` |
| 0x811A New Order | Market Watch ctx | `0x1412703e0` |
| 0x8105 New Order | trade tab | `0x140fa7a80` |
| 0x8155/56/57/58 | BuyLimit/BuyStop/SellLimit/SellStop | `0x140a54d50` / `0x140a6d130` / `0x140a6d240` / `0x140a6d350` |
| 0x838F One Click | Alt+T | `0x140a64110` |
| 0x9910 Close All | trade tab | `0x140fa9f20` |

## 3. Order-window creation path (ordinary-tool observation)

```
F9/menu 0x8050 → handler 0x140bc6a90 (builds order request; fields 0x237, 0x8e)
  → 0x1404ed860 (create window) → 0x1410ac410 (Order-window factory)
    → 0x14108ecb0 / constructor 0x14104f500 stores resource id 0x965 (=2405)
      → 0x1404ed4e0 loads the DIALOG template (type 5 = RT_DIALOG)
```

## 4. Internal command message 0x419 (ordinary-tool observation)

Helper `0x140ee18e0` implements the internal router:

```
mov r8d, edi          ; wParam = command id
mov rcx, [rsi+0x40]   ; rcx = target window handle (object+0x40)
mov edx, 0x419        ; undocumented message
xor r9d, r9d          ; lParam = 0
call [0x1428d9218]    ; signature (hwnd, msg, wparam, 0) — matches SendMessageW
```

then stores state at `[obj+0x1dc]`, arms a 500 ms timer, and calls
`(hwnd, 0, 1)` (likely `InvalidateRect`). Callers include the thunks for
0x8050 and 0x8052.

`0x419` lies in the WM_USER range (`0x400–0x7FFF`), the documented safe
range for app-private messages.

## 5. Import table encryption (limitation)

The IAT is encrypted: `.rdata` pointer slots (`0x1428d8000–0x1428e0000`)
hold high-entropy data that the loader decrypts at startup. Therefore the
exact Win32 function behind each slot (SendMessageW vs SendMessageTimeoutW
etc.) **cannot be named statically**; signatures were matched instead.

## 6. Encrypted code sections (limitation)

`.cod0/.cod1/.cod2` are decrypted at runtime; linear disassembly beyond
`~0x143000000` is garbage. Window class names and the receiver of message
0x419 likely live there — this is why the library discovers windows by
**process name** (`terminal64.exe`) instead of class names, and why the
One Click Trading SELL/BUY buttons have **no automation-safe handle**.

## 7. False leads (recorded to avoid repeating them)

- `cmp X, 0x419` sites in the disassembly compare the **Russian LCID**
  (`0x0419`) read from config at `[obj+0x104]` — not message dispatch.
- `mov eax, 0x8050` at `0x1402bdd9a` is a stack allocation size, not a
  command constant.

## Re-extraction checklist (after an MT5 update)

1. Verify SHA-256 changed → re-run the resource parsers for menus,
   accelerators, dialog 2405.
2. Re-scan `.rdata` for the `[handler][0x111][cmd][cmd][0x3a]` pattern and
   diff command ids.
3. Re-locate the `mov edx,0x419` sender (`mov r8d,<cmd>` preceding a call
   through a `.rdata` slot) to confirm the internal message still applies.
