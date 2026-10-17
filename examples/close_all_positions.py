"""Close all open positions via the Trade-tab command id (0x9910).

    python examples/close_all_positions.py [--dry-run]
"""

import sys

from mt5auto import MT5Terminal, ids


def main() -> int:
    dry = "--dry-run" in sys.argv
    t = MT5Terminal.find()
    print(f"attached: {t!r}")
    if dry:
        print(f"dry-run: would PostMessageW(WM_COMMAND, 0x{ids.Command.CLOSE_ALL:04X}, 0)")
        return 0
    t.close_all_positions()
    print("Close All command posted (0x9910).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
