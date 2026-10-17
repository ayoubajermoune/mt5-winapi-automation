"""Tests that run everywhere (no Windows required) — they validate the
extracted identifier tables, which are plain data."""

import unittest

from mt5auto import ids


class CommandIdsTest(unittest.TestCase):
    def test_new_order_is_menu_and_accelerator_id(self):
        self.assertEqual(ids.Command.NEW_ORDER, 0x8050)
        self.assertEqual(ids.Command.NEW_ORDER, 32848)

    def test_order_type_context_ids(self):
        self.assertEqual(
            (ids.Command.BUY_LIMIT, ids.Command.BUY_STOP,
             ids.Command.SELL_LIMIT, ids.Command.SELL_STOP),
            (0x8155, 0x8156, 0x8157, 0x8158),
        )

    def test_close_all(self):
        self.assertEqual(ids.Command.CLOSE_ALL, 0x9910)

    def test_wm_command_matches_user32_value(self):
        self.assertEqual(ids.WM_COMMAND, 0x0111)

    def test_internal_msg_in_wm_user_range(self):
        # 0x419 is in the WM_USER (0x400..0x7FFF) private range — required
        # for a custom message to be safe per Microsoft docs.
        self.assertTrue(0x0400 <= ids.MT5_INTERNAL_CMD_MSG <= 0x7FFF)


class DialogIdsTest(unittest.TestCase):
    def test_order_dialog_id(self):
        self.assertEqual(ids.DIALOG_ORDER, 2405)
        self.assertEqual(ids.DIALOG_ORDER, 0x965)

    def test_order_type_buttons_are_contiguous(self):
        self.assertEqual(len(ids.OrderControl.ORDER_TYPE_BUTTONS), 7)
        self.assertEqual(ids.OrderControl.ORDER_TYPE_BUTTONS[0], 0x2B6C)
        self.assertEqual(ids.OrderControl.ORDER_TYPE_BUTTONS[-1], 0x2B72)

    def test_order_control_ids_unique(self):
        values = [v for k, v in vars(ids.OrderControl).items()
                  if not k.startswith("_") and isinstance(v, int)]
        self.assertEqual(len(values), len(set(values)), "duplicate control ids")


class TermsDialogTest(unittest.TestCase):
    def test_one_click_terms(self):
        self.assertEqual(ids.DIALOG_ONE_CLICK_TERMS, 578)
        self.assertEqual(ids.OneClickTermsControl.ACCEPT_BUTTON, 1)
        self.assertEqual(ids.OneClickTermsControl.CANCEL_BUTTON, 2)


class ProvenanceTest(unittest.TestCase):
    def test_sha256_pinned(self):
        self.assertEqual(len(ids.TERMINAL_SHA256), 64)


if __name__ == "__main__":
    unittest.main()
