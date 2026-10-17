import time
import unittest

from logic import (
    allow_attempt,
    duplicate_slot,
    email_hash,
    is_callback_url,
    normalize_totp_secret,
    parse_proxy_uri,
    redact,
    should_restore_previous,
    totp_code,
)


class LogicTest(unittest.TestCase):
    def test_callback(self):
        good = "http://localhost:1455/auth/callback?code=abc&state=xyz"
        self.assertTrue(is_callback_url(good))
        self.assertFalse(is_callback_url("https://auth.openai.com/callback?code=abc"))
        self.assertFalse(is_callback_url("http://localhost:1456/auth/callback?code=abc"))
        self.assertFalse(is_callback_url(""))

    def test_proxy_parse(self):
        parsed = parse_proxy_uri("socks5://user:p%40ss@1.2.3.4:61234")
        self.assertEqual(parsed["server"], "http://1.2.3.4:61234")
        self.assertEqual(parsed["username"], "user")
        self.assertEqual(parsed["password"], "p@ss")

    def test_totp_shape(self):
        secret = normalize_totp_secret("jbsw y3dp-ehpk3pxp")
        code = totp_code(secret, now=1_700_000_000)
        self.assertEqual(len(code), 6)
        self.assertEqual(code, totp_code(secret, now=1_700_000_000))
        self.assertTrue(code.isdigit())

    def test_rate_limit(self):
        now = 1_000_000
        events = [{"t": now - 10, "kind": "auto"}, {"t": now - 20, "kind": "auto"}]
        allowed, fresh = allow_attempt(events, now, "auto")
        self.assertFalse(allowed)
        self.assertEqual(len(fresh), 2)
        allowed, _ = allow_attempt(events, now, "manual")
        self.assertTrue(allowed)
        old = [{"t": now - 7 * 3600, "kind": "auto"}]
        allowed, fresh = allow_attempt(old, now, "auto")
        self.assertTrue(allowed)
        self.assertEqual(fresh, [])

    def test_duplicate(self):
        panel = {"vm-05": "a@example.com", "vm-01": ""}
        saved = {"vm-02": "b@example.com"}
        self.assertEqual(duplicate_slot("A@example.com", "vm-04", panel, saved), "vm-05")
        self.assertIsNone(duplicate_slot("A@example.com", "vm-05", panel, saved))
        self.assertEqual(duplicate_slot("b@example.com", "vm-05", panel, saved), "vm-02")

    def test_restore(self):
        self.assertTrue(should_restore_previous(True, False))
        self.assertFalse(should_restore_previous(True, True))
        self.assertFalse(should_restore_previous(False, False))

    def test_redact_and_hash(self):
        self.assertIn("[jwt]", redact("token eyJhbGciOiJub25lIn0.payload.sig"))
        self.assertEqual(len(email_hash("A@Example.com")), 16)
        self.assertEqual(email_hash("A@Example.com"), email_hash("a@example.com"))


if __name__ == "__main__":
    unittest.main()
