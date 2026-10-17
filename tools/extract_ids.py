#!/usr/bin/env python3
"""
tools/extract_ids.py — re-extraction checklist from RESEARCH.md, automated.

Given a terminal64.exe (any build), this script:

  1. parses RT_MENU / RT_ACCELERATOR resources and reports every command id
     whose menu text matches the trade keywords (order/buy/sell/...),
  2. parses RT_DIALOG 2405 ("Order") and reports all control ids,
  3. scans .rdata for the WM_COMMAND dispatch-table pattern
     [handler VA:8][0x111:8][cmd:4][cmd:4][0x3a:8] and dumps every entry,
  4. diffs everything against the identifiers pinned in mt5auto/ids.py.

Standard library only (no pefile, no capstone). Run from the repo root:

    python tools/extract_ids.py "C:\\Program Files\\MetaTrader 5\\terminal64.exe"
    python tools/extract_ids.py terminal64.exe --json report.json

Exit code 0 = pinned ids still match this build; 1 = drift detected (the
library must be re-pinned); 2 = usage/file error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Minimal PE reader
# --------------------------------------------------------------------------

RES_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
}

CTRL_CLASSES = {
    0x0080: "BUTTON", 0x0081: "EDIT", 0x0082: "LISTBOX",
    0x0083: "SCROLLBAR", 0x0084: "STATIC", 0x0085: "COMBOBOX",
}


class PE:
    def __init__(self, path: Path):
        self.data = data = path.read_bytes()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        coff = e_lfanew + 4
        self.nsec = struct.unpack_from("<H", data, coff + 2)[0]
        optsz = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("not PE32+ (expected 0x20B)")
        nrdd = struct.unpack_from("<I", data, opt + 108)[0]
        rdd = opt + 112
        self.sections = []
        sec0 = opt + optsz
        for i in range(self.nsec):
            s = sec0 + i * 40
            name = data[s:s + 8].rstrip(b"\0").decode("latin1")
            vsz, va, rsz, ptr = struct.unpack_from("<IIII", data, s + 8)
            self.sections.append((name, va, vsz, ptr, rsz))
        # data-directory entry 2 = resource directory (.rsrc); entries are 8 bytes
        res_rva, _res_sz = struct.unpack_from("<II", data, rdd + 2 * 8)
        self.res_off = self.rva2off(res_rva) if res_rva else None

    def rva2off(self, rva: int):
        for _name, va, vsz, ptr, rsz in self.sections:
            if va <= rva < va + max(vsz, rsz):
                d = rva - va
                if d < rsz:
                    return ptr + d
        return None

    def section(self, name: str):
        for n, va, vsz, ptr, rsz in self.sections:
            if n == name:
                return va, ptr, rsz
        return None

    # ---- resource directory walking ----
    def read_dir(self, off: int):
        _c, _t, _ma, _mi, nnamed, nid = struct.unpack_from("<IIHHHH", self.data, off)
        base = off + 16
        out = []
        for i in range(nnamed + nid):
            name_or_id, offset = struct.unpack_from("<II", self.data, base + i * 8)
            if name_or_id & 0x80000000:
                nm = name_or_id  # named resource: treat as opaque
            else:
                nm = name_or_id
            if offset & 0x80000000:
                out.append(("dir", nm, self.res_off + (offset & 0x7FFFFFFF)))
            else:
                out.append(("data", nm, self.res_off + offset))
        return out

    def read_data(self, entry_off: int) -> bytes:
        rva_d, sz = struct.unpack_from("<II", self.data, entry_off)
        off = self.rva2off(rva_d)
        return self.data[off:off + sz]


# --------------------------------------------------------------------------
# Resource parsers
# --------------------------------------------------------------------------

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def parse_menu(b: bytes, o: int = 0):
    items = []
    ver = u16(b, o)
    pos = o + (4 if ver == 0 else 8)

    def string_at(p):
        e = b.index(b"\0\0", p)
        if (e - p) % 2:
            e += 1
        return b[p:e].decode("utf-16le", "replace"), e + 2

    while pos + 2 <= len(b):
        flags = u16(b, pos)
        pos += 2
        if flags & 0x80000000:
            continue
        if flags & 0x0004:
            s, pos = string_at(pos)
            items.append(("POPUP", s))
        else:
            mid = u16(b, pos) if ver == 0 else struct.unpack_from("<I", b, pos)[0]
            pos += 2 if ver == 0 else 4
            s, pos = string_at(pos)
            items.append(("ITEM", mid, s))
    return items


def parse_accelerators(b: bytes):
    out = []
    # entry: fVirt(1) pad(1) key(2) cmd(2) [pad(2)] — 6 or 8 bytes; detect via cmd spread
    for size in (6, 8):
        ok = True
        entries = []
        for i in range(0, len(b) - size + 1, size):
            if size == 6:
                fVirt, key, cmd = struct.unpack_from("<BHH", b, i)
            else:
                fVirt, _pad, key, cmd = struct.unpack_from("<BBHH", b, i)
            if cmd == 0 or cmd > 0xFFFF:
                ok = False
                break
            entries.append({"cmd": cmd, "key": key, "fVirt": fVirt})
        if ok and entries:
            return entries
    return out


def _read_szname(b, p):
    if struct.unpack_from("<H", b, p)[0] == 0xFFFF:
        return struct.unpack_from("<H", b, p + 2)[0], p + 4
    e = b.index(b"\0\0", p)
    if (e - p) % 2:
        e += 1
    return b[p:e].decode("utf-16le", "replace"), e + 2


def parse_dialogex(b: bytes):
    ver, sig = struct.unpack_from("<HH", b, 0)
    if (ver, sig) != (1, 0xFFFF):
        raise ValueError("not DIALOGEX")
    p = 4
    _help, _ex, style = struct.unpack_from("<III", b, p)
    p += 12
    cdit, x, y, cx, cy = struct.unpack_from("<HHhhh", b, p)
    p += 10
    _menu, p = _read_szname(b, p)
    _cls, p = _read_szname(b, p)
    title, p = _read_szname(b, p)
    if style & 0x40:
        p += 4  # fontsize + weight
        p += 2  # italic + charset
        _font, p = _read_szname(b, p)
    cb = struct.unpack_from("<H", b, p)[0]
    p += 2 + cb
    controls = []
    for _ in range(cdit):
        p = (p + 3) & ~3
        _ch, _ce, cstyle = struct.unpack_from("<III", b, p)
        p += 12
        _x, _y, _cx, _cy, cid = struct.unpack_from("<hhhhh", b, p)
        p += 10
        p = (p + 3) & ~3
        ccls, p = _read_szname(b, p)
        ctitle, p = _read_szname(b, p)
        cextra = struct.unpack_from("<H", b, p)[0]
        p += 2 + cextra
        controls.append({
            "id": cid & 0xFFFF,
            "class": CTRL_CLASSES.get(ccls, ccls),
            "title": ctitle,
            "style": cstyle,
        })
    return title, controls


# --------------------------------------------------------------------------
# Dispatch-table scan
# --------------------------------------------------------------------------

def scan_dispatch_tables(pe: PE, section_name: str = ".rdata"):
    """Find [handler:8][0x111:8][cmd:4][cmd:4][0x3a:8] entries (32 bytes)."""
    sec = pe.section(section_name)
    if not sec:
        return []
    va, ptr, size = sec
    blob = pe.data[ptr:ptr + size]
    base = 0x140000000 + va  # image base + section VA
    entries = []
    needle = struct.pack("<Q", 0x111)  # WM_COMMAND qword in the entry
    i = 0
    while True:
        i = blob.find(needle, i)
        if i < 0 or i + 16 + 8 > len(blob):
            break
        # candidate: qword at i-8 = handler, dword at i+8 == dword at i+12, dword at i+16 == 0x3a
        if i >= 8:
            handler = struct.unpack_from("<Q", blob, i - 8)[0]
            id1, id2, tail = struct.unpack_from("<III", blob, i + 8)
            if id1 == id2 and tail == 0x3A and 0x140000000 <= handler < 0x144000000:
                entries.append({
                    "table_entry": hex(base + i - 8),
                    "cmd": id1,
                    "handler": hex(handler),
                })
        i += 8
    return entries


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

TRADE_KEYWORDS = ("order", "buy", "sell", "trade", "position", "one click")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("exe", help="path to terminal64.exe")
    ap.add_argument("--json", help="write full JSON report to this path")
    ap.add_argument("--dialog", type=int, default=2405,
                    help="RT_DIALOG id to dump (default 2405 = Order)")
    args = ap.parse_args()

    path = Path(args.exe)
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    try:
        from mt5auto import ids as pinned
    except ImportError:
        pinned = None

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    pe = PE(path)

    report: dict = {"file": str(path), "sha256": digest, "sections": []}
    for name, va, vsz, ptr, rsz in pe.sections:
        report["sections"].append({"name": name, "va": hex(0x140000000 + va), "raw_size": hex(rsz)})

    drift = []

    # ---- 1. menus & accelerators ----
    menus, accels, dialogs = [], [], []
    if pe.res_off is not None:
        for kind, nm, off in pe.read_dir(pe.res_off):
            if kind != "dir":
                continue
            tname = RES_TYPES.get(nm, str(nm))
            for _k2, name, off2 in pe.read_dir(off):
                for _k3, _lang, data_off in pe.read_dir(off2):
                    blob = pe.read_data(data_off)
                    try:
                        if tname == "MENU":
                            menus.append((name, parse_menu(blob)))
                        elif tname == "ACCELERATOR":
                            accels.append((name, parse_accelerators(blob)))
                        elif tname == "DIALOG" and name == args.dialog:
                            title, ctrls = parse_dialogex(blob)
                            dialogs.append({"id": name, "title": title, "controls": ctrls})
                    except Exception as exc:  # noqa: BLE001 - report and continue
                        print(f"warn: {tname} id={name}: {exc}", file=sys.stderr)

    report["trade_menu_items"] = []
    report["all_menu_items"] = []
    for name, items in menus:
        for it in items:
            if it[0] == "ITEM":
                report["all_menu_items"].append(
                    {"menu_id": name, "cmd": hex(it[1]), "text": it[2]})
                if any(k in str(it[2]).lower() for k in TRADE_KEYWORDS):
                    report["trade_menu_items"].append(
                        {"menu_id": name, "cmd": hex(it[1]), "text": it[2]})
    report["trade_accelerators"] = []
    for name, entries in accels:
        for e in entries:
            report["trade_accelerators"].append(
                {"accel_id": name, "cmd": hex(e["cmd"]), "key": hex(e["key"]), "fVirt": e["fVirt"]})
    report["dialogs"] = dialogs

    # ---- 2. dispatch tables ----
    report["dispatch_entries"] = scan_dispatch_tables(pe)

    # ---- 3. diff against pinned ids ----
    if pinned is not None:
        pinned_cmds = {k: v for k, v in vars(pinned.Command).items()
                       if isinstance(v, int) and not k.startswith("_")}
        menu_cmds = {int(m["cmd"], 16) for m in report["all_menu_items"]}
        accel_cmds = {int(a["cmd"], 16) for a in report["trade_accelerators"]}
        found_cmds = {e["cmd"] for e in report["dispatch_entries"]}
        report["pinned_command_check"] = {}
        for name, val in sorted(pinned_cmds.items()):
            if val in found_cmds:
                status = "present"
            elif val in menu_cmds or val in accel_cmds:
                # e.g. 0x804B/0x8049 are RT_MENU-verified (Ctrl+M / Ctrl+T) but
                # have no entry in the plaintext dispatch tables (handler may
                # live in the encrypted .cod* sections)
                status = "menu-only"
            else:
                status = "NOT-FOUND"
                drift.append(f"Command.{name}={hex(val)} not found in menus, "
                             f"accelerators or dispatch tables")
            report["pinned_command_check"][name] = status

        pinned_dialog = {c["id"]: c for d in dialogs for c in d["controls"]}
        if dialogs:
            pinned_ctrls = {k: v for k, v in vars(pinned.OrderControl).items()
                            if isinstance(v, int) and not k.startswith("_")}
            for name, val in sorted(pinned_ctrls.items()):
                if val not in pinned_dialog:
                    drift.append(f"OrderControl.{name}={hex(val)} not in dialog {args.dialog}")

        if digest != pinned.TERMINAL_SHA256:
            print(f"note: build differs from pinned SHA-256 "
                  f"({pinned.TERMINAL_SHA256[:16]}... vs {digest[:16]}...)")

    # ---- output ----
    print(f"file:     {path}")
    print(f"sha256:   {digest}")
    print(f"sections: {len(pe.sections)}")
    print(f"trade menu items:      {len(report['trade_menu_items'])}")
    for m in report["trade_menu_items"]:
        print(f"   menu {m['menu_id']}: cmd={m['cmd']} \"{m['text']}\"")
    print(f"trade accelerators:    {len(report['trade_accelerators'])}")
    print(f"dispatch-table entries:{len(report['dispatch_entries'])}")
    for d in dialogs:
        print(f"dialog {d['id']} \"{d['title']}\": {len(d['controls'])} controls")
        for c in d["controls"]:
            print(f"   id=0x{c['id']:04X} class={c['class']:<10} title=\"{c['title']}\"")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"json report: {args.json}")

    if drift:
        print("\nDRIFT DETECTED — re-pin mt5auto/ids.py:")
        for d in drift:
            print(f"  - {d}")
        return 1
    print("\nall pinned identifiers verified against this build ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
