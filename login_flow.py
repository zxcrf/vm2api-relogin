"""Open the slot's Codex auth URL in a persistent Camoufox profile and log in.

stdin: one JSON object
  auth_url, proxy {server,username,password}, email, password, totp, profile_dir
  mode: "login" (default) or "dump"
stdout: one JSON object. Secrets are not written to stderr.
"""

import json
import os
import sys
import time
import traceback

from logic import (
    AUTH_HINT,
    HUMAN_HINT,
    PASSWORD_HINT,
    PHONE_HINT,
    SHOW_HINT,
    is_callback_url,
    redact,
    totp_code,
)

SHOT_DIR = os.environ.get("SHOT_DIR", "/shots")


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def log(msg):
    sys.stderr.write(str(msg).rstrip() + "\n")
    sys.stderr.flush()


def shot(page, name):
    path = os.path.join(SHOT_DIR, name)
    try:
        os.makedirs(SHOT_DIR, exist_ok=True)
        page.screenshot(path=path, full_page=True)
    except Exception:
        log(f"shot_fail {name}")
    return name


def first_visible(locator, limit=12):
    try:
        count = min(locator.count(), limit)
    except Exception:
        return None
    for index in range(count):
        element = locator.nth(index)
        try:
            if element.is_visible():
                return element
        except Exception:
            continue
    return None


def visible_all(locator, limit=20):
    try:
        count = min(locator.count(), limit)
    except Exception:
        return []
    found = []
    for index in range(count):
        element = locator.nth(index)
        try:
            if element.is_visible():
                found.append(element)
        except Exception:
            continue
    return found


def text_of(element):
    try:
        return (element.inner_text(timeout=1000) or "").strip()
    except Exception:
        return ""


class Flow:
    def __init__(self, context, payload):
        self.context = context
        self.payload = payload
        self.captured = None
        self.email_done = False
        self.password_done = False
        self.totp_done = False
        self.alt_clicks = 0
        self.auth_clicks = 0
        self.primary_clicks = 0
        self.hold = None
        self.last_action = None

    def on_request(self, request):
        url = request.url
        if is_callback_url(url):
            self.captured = url

    def attach(self, page):
        try:
            page.on("request", self.on_request)
        except Exception:
            pass

    def bind(self):
        self.context.on("page", self.attach)
        for page in list(self.context.pages):
            self.attach(page)

        def handle(route):
            url = route.request.url
            if is_callback_url(url):
                self.captured = url
                route.fulfill(status=200, content_type="text/html", body="<html><body>ok</body></html>")
                return
            route.continue_()

        self.context.route("**/*", handle)

    def page(self):
        chosen = None
        for candidate in reversed(list(self.context.pages)):
            try:
                if candidate.is_closed():
                    continue
            except Exception:
                continue
            chosen = candidate
            url = candidate.url or ""
            if is_callback_url(url) or "openai.com" in url or "chatgpt.com" in url:
                return candidate
        if chosen is not None:
            return chosen
        return self.context.new_page()

    def callback(self):
        if self.captured:
            return self.captured
        for candidate in list(self.context.pages):
            try:
                if is_callback_url(candidate.url):
                    self.captured = candidate.url
                    return self.captured
            except Exception:
                continue
        return None

    def find_email(self, page):
        return first_visible(
            page.locator(
                "input[type='email'], input[name='email' i], "
                "input[autocomplete='username'], input[autocomplete='email']"
            )
        )

    def find_password(self, page):
        return first_visible(page.locator("input[type='password']"))

    def find_otp(self, page):
        return visible_all(
            page.locator(
                "input[autocomplete='one-time-code'], input[name='code' i], "
                "input[inputmode='numeric'], input[name='otp' i]"
            )
        )

    def find_tel(self, page):
        return first_visible(page.locator("input[type='tel'], input[autocomplete='tel']"))

    def alert_text(self, page):
        parts = []
        for element in visible_all(page.locator("[role='alert'], [aria-invalid='true']"), limit=6):
            value = text_of(element)
            if value:
                parts.append(value)
        return redact(" ".join(parts))[:180]

    def body_head(self, page):
        try:
            return page.inner_text("body", timeout=2000)[:800]
        except Exception:
            return ""

    def signature(self, page):
        kinds = []
        if self.find_email(page):
            kinds.append("email")
        if self.find_password(page):
            kinds.append("password")
        if self.find_otp(page):
            kinds.append("otp")
        if self.find_tel(page):
            kinds.append("tel")
        url = ""
        try:
            url = (page.url or "").split("?", 1)[0]
        except Exception:
            pass
        return (url, tuple(kinds), self.alert_text(page)[:80])

    def click_matching(self, page, hint, skip_show=True):
        for element in visible_all(page.locator("a"), limit=30):
            href = ""
            try:
                href = element.get_attribute("href") or ""
            except Exception:
                pass
            label = text_of(element)
            if skip_show and SHOW_HINT.search(label):
                continue
            if PHONE_HINT.search(label) and hint is not PHONE_HINT:
                continue
            if "password" in href.lower() and hint is PASSWORD_HINT:
                element.click()
                return True
            if hint.search(label):
                element.click()
                return True
        for element in visible_all(page.locator("button, [role='button']"), limit=30):
            label = text_of(element)
            if skip_show and SHOW_HINT.search(label):
                continue
            if PHONE_HINT.search(label) and hint is not PHONE_HINT:
                continue
            if hint.search(label):
                element.click()
                return True
        return False

    def click_primary(self, page):
        for element in visible_all(page.locator("button[type='submit']"), limit=8):
            label = text_of(element)
            if PHONE_HINT.search(label) or SHOW_HINT.search(label):
                continue
            lowered = label.lower()
            if any(word in lowered for word in ("google", "apple", "microsoft")):
                continue
            element.click()
            return True
        for element in visible_all(page.locator("button, [role='button']"), limit=20):
            label = text_of(element)
            lowered = label.lower()
            if not label:
                continue
            if any(word in lowered for word in ("google", "apple", "microsoft")):
                continue
            if PHONE_HINT.search(label) or SHOW_HINT.search(label):
                continue
            element.click()
            return True
        return False

    def fill(self, element, value):
        element.click(timeout=5000)
        element.fill(value, timeout=5000)

    def fail(self, page, code, detail=""):
        name = shot(page, f"{code}.png")
        return {"ok": False, "code": code, "detail": redact(detail)[:180], "shot": name}

    def dump(self, page):
        rows = []
        for element in visible_all(page.locator("input, button, a"), limit=40):
            try:
                tag = element.evaluate("el => el.tagName")
                attrs = element.evaluate(
                    """el => ({
                        type: el.getAttribute('type'),
                        name: el.getAttribute('name'),
                        autocomplete: el.getAttribute('autocomplete'),
                        inputmode: el.getAttribute('inputmode')
                    })"""
                )
            except Exception:
                continue
            rows.append({"tag": tag, "text": text_of(element)[:80], **attrs})
        shot(page, "dump.png")
        return {
            "ok": True,
            "mode": "dump",
            "url_path": (page.url or "").split("?", 1)[0],
            "title": page.title(),
            "controls": rows,
        }

    def fail_if_unchanged(self, page):
        alert = self.alert_text(page)
        if self.last_action == "password" and self.find_password(page) and not self.find_otp(page):
            if alert:
                return self.fail(page, "password_rejected", alert)
        if self.last_action == "totp" and self.find_otp(page) and alert:
            return self.fail(page, "totp_rejected", alert)
        if (
            self.last_action == "email"
            and self.find_email(page)
            and alert
            and not self.find_password(page)
            and not self.find_otp(page)
        ):
            return self.fail(page, "email_rejected", alert)
        return None

    def step(self, page):
        if self.find_tel(page) and not self.find_password(page) and self.email_done:
            return self.fail(page, "phone_required", self.alert_text(page))
        head = self.body_head(page)
        if HUMAN_HINT.search(head):
            return self.fail(page, "security_check", head[:120])

        email = self.find_email(page)
        password = self.find_password(page)
        otp = self.find_otp(page)

        if email and not password and not self.email_done:
            self.fill(email, self.payload["email"])
            self.click_primary(page)
            self.email_done = True
            self.last_action = "email"
            log("state=email")
            return "wait"

        if password and not self.password_done:
            self.fill(password, self.payload["password"])
            self.click_primary(page)
            self.password_done = True
            self.last_action = "password"
            log("state=password")
            return "wait"

        if otp and not self.totp_done:
            code = totp_code(self.payload["totp"])
            if len(otp) >= 6:
                for element, digit in zip(otp, code):
                    self.fill(element, digit)
            else:
                self.fill(otp[0], code)
            self.click_primary(page)
            self.totp_done = True
            self.last_action = "totp"
            log("state=totp")
            return "wait"

        if self.email_done and not self.password_done and self.alt_clicks < 3:
            if self.click_matching(page, PASSWORD_HINT):
                self.alt_clicks += 1
                self.last_action = "password_alt"
                log("state=password_alt")
                return "wait"

        if (self.password_done or self.email_done) and not self.totp_done and self.auth_clicks < 2:
            if self.click_matching(page, AUTH_HINT):
                self.auth_clicks += 1
                self.last_action = "auth_app"
                log("state=auth_app")
                return "wait"

        if self.email_done and not self.password_done and not password and self.alt_clicks >= 3:
            if otp or "code" in (page.url or ""):
                return self.fail(page, "email_otp_required", "password field was not offered")

        if self.primary_clicks < 4 and (self.password_done or self.totp_done or not email):
            if self.click_primary(page):
                self.primary_clicks += 1
                self.last_action = "consent"
                log("state=consent")
                return "wait"

        return "wait"

    def run(self):
        page = self.page()
        page.set_default_timeout(8000)
        log("state=open")
        page.goto(self.payload["auth_url"], timeout=90000, wait_until="domcontentloaded")
        if self.payload.get("mode") == "dump":
            time.sleep(6)
            return self.dump(self.page())

        deadline = time.time() + 420
        idle_since = time.time()
        previous = None
        while time.time() < deadline:
            page = self.page()
            found = self.callback()
            if found:
                log("state=callback")
                return {"ok": True, "callback": found}
            current = self.signature(page)
            if self.hold:
                if current != self.hold[0]:
                    self.hold = None
                    idle_since = time.time()
                elif time.time() < self.hold[1]:
                    time.sleep(0.35)
                    continue
                else:
                    failed = self.fail_if_unchanged(page)
                    self.hold = None
                    if failed:
                        return failed
            if current != previous:
                idle_since = time.time()
                previous = current
            outcome = self.step(page)
            if isinstance(outcome, dict):
                return outcome
            self.hold = (self.signature(self.page()), time.time() + 20)
            if time.time() - idle_since > 50 and self.email_done:
                page = self.page()
                alert = self.alert_text(page)
                if self.find_password(page) and self.password_done and not self.find_otp(page):
                    return self.fail(page, "password_rejected" if alert else "password_unchanged", alert)
                if self.password_done and not self.totp_done and not self.find_otp(page) and not self.find_password(page):
                    return self.fail(page, "totp_missing", alert or "no authenticator field")
                return self.fail(page, "stuck", alert or (page.url or "").split("?", 1)[0])
            time.sleep(0.3)
        return self.fail(self.page(), "timeout", "login did not finish within 7 minutes")


def load_fingerprint(profile):
    path = os.path.join(profile, "fingerprint.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    from camoufox.fingerprints import generate_fingerprint

    generated = generate_fingerprint(os="windows")
    safe = json.loads(json.dumps(generated, default=str))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(safe, handle)
    return safe


def launch_and_run(payload):
    from camoufox.sync_api import Camoufox

    profile = payload["profile_dir"]
    user_data = os.path.join(profile, "userdata")
    os.makedirs(user_data, exist_ok=True)
    fingerprint = None
    try:
        fingerprint = load_fingerprint(profile)
    except Exception as exc:
        log("fingerprint_skip " + redact(exc))

    kwargs = {
        "headless": "virtual",
        "persistent_context": True,
        "user_data_dir": user_data,
        "proxy": payload["proxy"],
        "geoip": True,
        "os": "windows",
        "humanize": True,
        "enable_cache": True,
    }
    if fingerprint:
        kwargs["fingerprint"] = fingerprint
        kwargs["i_know_what_im_doing"] = True

    try:
        context_manager = Camoufox(**kwargs)
        context = context_manager.__enter__()
    except Exception:
        if not fingerprint:
            raise
        log("fingerprint_rejected")
        kwargs.pop("fingerprint", None)
        context_manager = Camoufox(**kwargs)
        context = context_manager.__enter__()
    try:
        flow = Flow(context, payload)
        flow.bind()
        return flow.run()
    finally:
        context_manager.__exit__(None, None, None)


def main():
    try:
        payload = json.load(sys.stdin)
        result = launch_and_run(payload)
    except Exception as exc:
        log(traceback.format_exc().splitlines()[-1])
        result = {"ok": False, "code": "browser_error", "detail": redact(exc)}
    emit(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
