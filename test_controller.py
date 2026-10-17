import os
import tempfile
import time
import unittest
from unittest import mock

os.environ["RELOGIN_ROOT"] = tempfile.mkdtemp()
_env = os.path.join(os.environ["RELOGIN_ROOT"], ".env")
with open(_env, "w", encoding="utf-8") as handle:
    handle.write("VM2API_API_KEY=test\n")
os.environ["VM2API_ENV"] = _env
import controller  # noqa: E402

EMAIL = "a@example.com"
VM = "vm1"


def fake_api(method, path, body=None, timeout=90):
    if path == "/api/panel/vms":
        return []
    if path.endswith("/reveal"):
        return {"uri": "socks5://u:p@1.2.3.4:80"}
    if path.endswith("/generate-auth-url"):
        return {"auth_url": "https://auth", "session_id": "s"}
    if path.endswith("/test-chat"):
        return {"ok": True}
    if method == "GET":
        return {"vm": {"proxy_id": "p1"}}
    return {}


class ControllerTest(unittest.TestCase):
    def setUp(self):
        os.makedirs(controller.SECRETS, exist_ok=True)
        controller.save_json(controller.STATE_PATH, {"events": {}, "last": {}})
        patches = [
            mock.patch.object(controller, "accounts", return_value={VM: {"email": EMAIL}}),
            mock.patch.object(controller, "list_slots", return_value=[{"id": VM, "status": "running"}]),
            mock.patch.object(controller, "secret_values", return_value=("pw", "JBSWY3DPEHPK3PXP")),
            mock.patch.object(controller, "api", side_effect=fake_api),
            mock.patch.object(controller, "PROFILES", tempfile.mkdtemp()),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def events(self):
        return controller.state()["events"].get(controller.email_hash(EMAIL), [])

    def run_job(self, kind, browser):
        job = {"id": "j", "vm_id": VM, "status": "running", "message": ""}
        with mock.patch.object(controller, "browser_login", side_effect=browser):
            controller.run_relogin(job, kind)
        return job

    def test_success_counts_once(self):
        job = self.run_job("manual", lambda job, payload: {"ok": True, "callback": "c"})
        self.assertEqual(job["status"], "done")
        self.assertEqual(len(self.events()), 1)

    def test_browser_failure_counts_once(self):
        job = self.run_job("manual", lambda job, payload: {"ok": False, "code": "bad"})
        self.assertEqual(job["status"], "error")
        self.assertEqual(len(self.events()), 1)

    def test_rejected_attempt_does_not_count(self):
        now = time.time()
        full = [{"t": now, "kind": "auto"}, {"t": now, "kind": "auto"}]
        controller.save_json(controller.STATE_PATH, {"events": {controller.email_hash(EMAIL): full}, "last": {}})
        browser = mock.Mock()
        job = self.run_job("auto", browser)
        self.assertEqual(job["status"], "error")
        self.assertIn("上限", job["message"])
        browser.assert_not_called()
        self.assertEqual(len(self.events()), 2)

    def test_prelogin_failure_does_not_count(self):
        with mock.patch.object(controller, "duplicate_slot", return_value="vm2"):
            job = self.run_job("manual", mock.Mock())
        self.assertEqual(job["status"], "error")
        self.assertEqual(self.events(), [])

    def test_sweep_failure_does_not_count(self):
        slot = {"id": VM, "status": "running", "password_set": True, "saved_email": EMAIL}
        with mock.patch.object(controller, "list_slots", return_value=[slot]), mock.patch.object(
            controller, "api", return_value={"ok": False, "error": {"code": "rate_limited"}}
        ):
            for _ in range(6):
                controller.sweep_once()
        self.assertEqual(self.events(), [])
        self.assertEqual(controller.state()["last"][VM]["code"], "rate_limited")


if __name__ == "__main__":
    unittest.main()
