"""Admin page and 401 sweep for fingerprint-browser relogin.

Does not modify vm2api. Talks to the panel API with the master key after the
operator signs in with the panel password. Account passwords stay encrypted
on disk and are passed to the browser container on stdin.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from logic import (
    allow_attempt,
    duplicate_slot,
    email_hash,
    fresh_events,
    normalize_totp_secret,
    parse_proxy_uri,
    redact,
    should_restore_previous,
)

ROOT = os.environ.get("RELOGIN_ROOT", "/opt/vm2api-relogin")
VM2API_BASE = os.environ.get("VM2API_BASE", "http://127.0.0.1:8787").rstrip("/")
VM2API_ENV = os.environ.get("VM2API_ENV", "/opt/vm2api/.env")
LISTEN = os.environ.get("LISTEN", "10.66.0.2:8791")
PREFIX = os.environ.get("PUBLIC_PREFIX", "/relogin").rstrip("/")
ALLOWED_HOSTS = {"vm2api.baobao.click", "10.66.0.2", "127.0.0.1"}
IMAGE = os.environ.get("BROWSER_IMAGE", "vm2api-relogin-poc:0")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS = os.path.join(ROOT, "secrets")
PROFILES = os.path.join(ROOT, "profiles")
SHOTS = os.path.join(ROOT, "shots")
STATE_PATH = os.path.join(SECRETS, "state.json")
ACCOUNTS_PATH = os.path.join(SECRETS, "accounts.json")
SWEEP_S = 15 * 60

lock = threading.Lock()
jobs = {}
running_vm = None
login_failures = {}


def read_env_value(path, name):
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key == name:
                return value.strip().strip("'\"")
    raise KeyError(name)


API_KEY = read_env_value(VM2API_ENV, "VM2API_API_KEY")


def key_file(name):
    path = os.path.join(SECRETS, name)
    os.makedirs(SECRETS, mode=0o700, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "wb") as handle:
            handle.write(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    with open(path, "rb") as handle:
        return handle.read()


SESSION_KEY = key_file("session.key")
FERNET_KEY = key_file("fernet.key")


def fernet():
    from cryptography.fernet import Fernet

    digest = hashlib.sha256(FERNET_KEY).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(text):
    return fernet().encrypt(text.encode()).decode()


def decrypt(token):
    return fernet().decrypt(token.encode()).decode()


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def accounts():
    return load_json(ACCOUNTS_PATH, {})


def state():
    return load_json(STATE_PATH, {"events": {}, "last": {}})


def api(method, path, body=None, timeout=90):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        VM2API_BASE + path,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + API_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"ok": False, "error": {"message": raw[:240]}}
        message = payload.get("error", {}).get("message") or raw[:240]
        raise RuntimeError(redact(message)) from None
    if isinstance(payload, dict) and payload.get("ok") is False:
        message = (payload.get("error") or {}).get("message") or "vm2api error"
        raise RuntimeError(redact(message))
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def panel_login(username, password):
    request = urllib.request.Request(
        VM2API_BASE + "/api/panel/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except urllib.error.HTTPError:
        return None
    if not payload.get("ok") or payload.get("role") != "admin":
        return None
    return payload.get("user") or username


def sign_session(username):
    exp = int(time.time()) + 12 * 3600
    body = f"{username}|admin|{exp}".encode()
    sig = hmac.new(SESSION_KEY, body, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(body).decode() + "." + sig


def read_session(cookie_header):
    if not cookie_header:
        return None
    token = None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("relogin_session="):
            token = part.split("=", 1)[1]
    if not token or "." not in token:
        return None
    raw, sig = token.split(".", 1)
    try:
        body = base64.urlsafe_b64decode(raw.encode())
    except Exception:
        return None
    expected = hmac.new(SESSION_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    username, role, exp = body.decode().split("|")
    if role != "admin" or int(exp) < time.time():
        return None
    return username


def list_slots():
    data = api("GET", "/api/panel/vms", timeout=30)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or data.get("vms") or []
    else:
        items = []
    rows = []
    saved = accounts()
    current = state()
    for vm in items:
        if not isinstance(vm, dict):
            continue
        vm_id = vm.get("id")
        record = saved.get(vm_id) or {}
        job = None
        with lock:
            for item in jobs.values():
                if item["vm_id"] == vm_id and item["status"] == "running":
                    job = {"status": item["status"], "message": item["message"]}
        rows.append(
            {
                "id": vm_id,
                "status": vm.get("status"),
                "schedulable": vm.get("schedulable"),
                "panel_email": vm.get("email") or "",
                "saved_email": record.get("email") or "",
                "password_set": bool(record.get("password")),
                "totp_set": bool(record.get("totp")),
                "last": current["last"].get(vm_id),
                "job": job,
            }
        )
    return rows


def save_account(vm_id, email, password, totp):
    email = email.strip()
    if "@" not in email:
        raise ValueError("需要邮箱")
    saved = accounts()
    current = saved.get(vm_id) or {}
    if password:
        current["password"] = encrypt(password)
    elif not current.get("password"):
        raise ValueError("还没有密码")
    if totp:
        normalize_totp_secret(totp)
        current["totp"] = encrypt(totp)
    elif not current.get("totp"):
        raise ValueError("还没有 TOTP 密钥")
    current["email"] = email
    current["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    saved[vm_id] = current
    save_json(ACCOUNTS_PATH, saved)
    return current


def secret_values(record):
    return decrypt(record["password"]), decrypt(record["totp"])


def record_result(vm_id, email, ok, code, detail, kind):
    current = state()
    current["last"][vm_id] = {
        "ok": ok,
        "code": code,
        "detail": redact(detail)[:180],
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if email:
        bucket = current["events"].setdefault(email_hash(email), [])
        bucket.append({"t": time.time(), "kind": kind})
        current["events"][email_hash(email)] = fresh_events(bucket, time.time())
    save_json(STATE_PATH, current)


def browser_login(job, payload):
    name = "relogin-" + job["id"]
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shot_dir = os.path.join(SHOTS, job["id"])
    os.makedirs(shot_dir, exist_ok=True)
    os.chmod(shot_dir, 0o700)
    subprocess.run(["chown", "-R", "10791:10791", shot_dir, payload["profile_dir"]], check=False)
    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        name,
        "--memory",
        "2g",
        "--shm-size",
        "1g",
        "--cpus",
        "2",
        "--pids-limit",
        "512",
        "--security-opt",
        "no-new-privileges",
        "-e",
        "PYTHONPATH=/work/app",
        "-e",
        "SHOT_DIR=/shots",
        "-v",
        APP_DIR + ":/work/app:ro",
        "-v",
        payload["profile_dir"] + ":/profile",
        "-v",
        shot_dir + ":/shots",
        IMAGE,
        "python",
        "/work/app/login_flow.py",
    ]
    docker_payload = {
        "auth_url": payload["auth_url"],
        "proxy": payload["proxy"],
        "email": payload["email"],
        "password": payload["password"],
        "totp": payload["totp"],
        "profile_dir": "/profile",
        "mode": "login",
    }
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc.stdin.write(json.dumps(docker_payload))
    proc.stdin.close()

    def pump():
        for line in proc.stderr:
            text = line.strip()
            if text.startswith("state="):
                job["message"] = "浏览器：" + text.split("=", 1)[1]
            elif text:
                print("browser", job["id"], redact(text)[:180], flush=True)

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    try:
        stdout, _ = proc.communicate(timeout=450)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.kill()
        raise RuntimeError("browser timed out")
    thread.join(timeout=2)
    line = (stdout or "").strip().splitlines()
    if not line:
        raise RuntimeError("browser returned no result")
    return json.loads(line[-1])


def run_relogin(job, kind):
    global running_vm
    vm_id = job["vm_id"]
    exchanged = False
    was_running = False
    email = ""
    try:
        saved = accounts()
        record = saved.get(vm_id)
        if not record:
            raise RuntimeError("这个槽还没有保存账号")
        email = record["email"]
        slots = list_slots()
        panel = {row["id"]: row.get("panel_email") or "" for row in slots}
        stored = {row["id"]: row.get("saved_email") or "" for row in slots}
        other = duplicate_slot(email, vm_id, panel, stored)
        if other:
            raise RuntimeError(f"这个邮箱已经在 {other}，不能两个槽共用 refresh token")
        events = state()["events"].get(email_hash(email), [])
        allowed, _ = allow_attempt(events, time.time(), kind)
        if not allowed:
            raise RuntimeError("这个账号 6 小时内的登录次数到了上限")
        was_running = any(row["id"] == vm_id and row.get("status") == "running" for row in slots)
        job["message"] = "正在关闭槽位"
        api("POST", f"/api/panel/vms/{vm_id}/stop", {}, timeout=120)
        job["message"] = "正在读取代理"
        detail = api("GET", f"/api/panel/vms/{vm_id}")
        vm = detail.get("vm") if isinstance(detail, dict) and isinstance(detail.get("vm"), dict) else detail
        proxy = {}
        if isinstance(detail, dict) and isinstance(detail.get("proxy"), dict):
            proxy = detail["proxy"]
        elif isinstance(vm, dict) and isinstance(vm.get("proxy"), dict):
            proxy = vm["proxy"]
        proxy_id = (vm or {}).get("proxy_id") or proxy.get("id")
        if not proxy_id:
            raise RuntimeError("槽位没有绑定代理")
        revealed = api("POST", f"/api/panel/proxies/{proxy_id}/reveal", {})
        proxy = parse_proxy_uri(revealed.get("uri") or "")
        job["message"] = "正在生成授权链接"
        generated = api("POST", f"/api/panel/vms/{vm_id}/oauth/generate-auth-url", {})
        password, totp = secret_values(record)
        profile = os.path.join(PROFILES, email_hash(email))
        os.makedirs(profile, mode=0o700, exist_ok=True)
        job["message"] = "正在用指纹浏览器登录"
        result = browser_login(
            job,
            {
                "auth_url": generated["auth_url"],
                "proxy": proxy,
                "email": email,
                "password": password,
                "totp": totp,
                "profile_dir": profile,
            },
        )
        if not result.get("ok"):
            code = result.get("code") or "login_failed"
            extra = result.get("detail") or ""
            raise RuntimeError(code + (": " + extra if extra else ""))
        job["message"] = "正在写入凭证"
        api(
            "POST",
            f"/api/panel/vms/{vm_id}/oauth/exchange-code",
            {"session_id": generated["session_id"], "code": result["callback"]},
            timeout=120,
        )
        exchanged = True
        job["message"] = "正在启动槽位"
        api("POST", f"/api/panel/vms/{vm_id}/start", {}, timeout=180)
        job["message"] = "正在测试"
        verified = None
        for _ in range(4):
            verified = api(
                "POST",
                f"/api/panel/vms/{vm_id}/test-chat",
                {"prompt": "Reply with the single word pong.", "max_tokens": 16},
                timeout=150,
            )
            if verified.get("ok"):
                break
            time.sleep(8)
        if not verified or not verified.get("ok"):
            err = (verified or {}).get("error") or {}
            code = err.get("code") or "verify_failed"
            if code in {"oauth_expired", "oauth_unauthorized"}:
                api("POST", f"/api/panel/vms/{vm_id}/stop", {}, timeout=120)
            message = err.get("message") or code
            raise RuntimeError(f"{code}: {redact(message)[:180]}")
        record_result(vm_id, email, True, "ok", "测试通过", kind)
        job["status"] = "done"
        job["message"] = "登录成功，测试已通过"
    except Exception as exc:
        detail = redact(exc)
        if should_restore_previous(was_running, exchanged):
            try:
                api("POST", f"/api/panel/vms/{vm_id}/start", {}, timeout=180)
                detail += "；已重新打开槽位"
            except Exception as restore_error:
                detail += "；重新打开失败：" + redact(restore_error)
        record_result(vm_id, email, False, "error", detail, kind)
        job["status"] = "error"
        job["message"] = detail[:300]
    finally:
        with lock:
            global_running = running_vm
            if global_running == vm_id:
                set_running(None)


def set_running(vm_id):
    global running_vm
    running_vm = vm_id


def start_job(vm_id, kind):
    with lock:
        if running_vm:
            raise RuntimeError(f"{running_vm} 正在登录，请等它结束")
        set_running(vm_id)
        job_id = secrets.token_hex(8)
        job = {"id": job_id, "vm_id": vm_id, "status": "running", "message": "已开始", "kind": kind}
        jobs[job_id] = job
    thread = threading.Thread(target=run_relogin, args=(job, kind), daemon=True)
    thread.start()
    return job


def sweep_once():
    try:
        slots = list_slots()
    except Exception as exc:
        print("sweep_list_failed", redact(exc), flush=True)
        return
    for slot in slots:
        if slot.get("status") != "running" or not slot.get("password_set"):
            continue
        if slot.get("job"):
            continue
        vm_id = slot["id"]
        try:
            result = api(
                "POST",
                f"/api/panel/vms/{vm_id}/test-chat",
                {"prompt": "Reply with the single word pong.", "max_tokens": 16},
                timeout=150,
            )
        except Exception as exc:
            print("sweep_test_failed", vm_id, redact(exc), flush=True)
            continue
        if result.get("ok"):
            continue
        code = (result.get("error") or {}).get("code") or "verify_failed"
        print("sweep", vm_id, code, flush=True)
        if code != "oauth_expired":
            record_result(vm_id, slot.get("saved_email") or "", False, code, "巡检发现，未自动登录", "auto")
            continue
        try:
            start_job(vm_id, "auto")
        except Exception as exc:
            print("sweep_skip", vm_id, redact(exc), flush=True)
        return


def sweep_loop():
    time.sleep(90)
    while True:
        try:
            sweep_once()
        except Exception as exc:
            print("sweep_error", redact(exc), flush=True)
        time.sleep(SWEEP_S)


class Handler(BaseHTTPRequestHandler):
    server_version = "relogin"

    def log_message(self, fmt, *args):
        print("http", self.address_string(), redact(fmt % args), flush=True)

    def path_only(self):
        return self.path.split("?", 1)[0]

    def send_json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, status, html):
        raw = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 32_000:
            raise ValueError("body too large")
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(":")[0].lower()
        name = (urllib.parse.urlparse(origin).hostname or "").lower()
        return name == host or name in ALLOWED_HOSTS

    def authorized(self):
        return read_session(self.headers.get("Cookie"))

    def require_admin(self):
        if self.headers.get("X-Requested-With") != "relogin":
            self.send_json(400, {"error": "missing header"})
            return False
        if not self.origin_ok():
            self.send_json(403, {"error": "bad origin"})
            return False
        if not self.authorized():
            self.send_json(401, {"error": "需要登录"})
            return False
        return True

    def do_GET(self):
        path = self.path_only()
        if path == PREFIX:
            self.send_response(302)
            self.send_header("Location", PREFIX + "/")
            self.end_headers()
            return
        if path == PREFIX + "/":
            with open(os.path.join(APP_DIR, "page.html"), encoding="utf-8") as handle:
                self.send_html(200, handle.read())
            return
        if path == PREFIX + "/api/slots":
            if not self.require_admin():
                return
            try:
                self.send_json(200, {"slots": list_slots()})
            except Exception as exc:
                self.send_json(502, {"error": redact(exc)})
            return
        if path.startswith(PREFIX + "/api/jobs/"):
            if not self.require_admin():
                return
            job = jobs.get(path.rsplit("/", 1)[-1])
            if not job:
                self.send_json(404, {"error": "没有这个任务"})
                return
            self.send_json(200, {"id": job["id"], "vm_id": job["vm_id"], "status": job["status"], "message": job["message"]})
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path_only()
        if self.headers.get("X-Requested-With") != "relogin" or not self.origin_ok():
            self.send_json(400, {"error": "bad request"})
            return
        try:
            body = self.read_body()
        except Exception:
            self.send_json(400, {"error": "请求无法解析"})
            return
        if path == PREFIX + "/api/login":
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            now = time.time()
            recent = [item for item in login_failures.get(ip, []) if now - item < 600]
            if len(recent) >= 8:
                self.send_json(429, {"error": "登录尝试太多，等十分钟"})
                return
            user = panel_login(body.get("username") or "", body.get("password") or "")
            if not user:
                recent.append(now)
                login_failures[ip] = recent
                self.send_json(401, {"error": "用户名或密码错误"})
                return
            login_failures.pop(ip, None)
            token = sign_session(user)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header(
                "Set-Cookie",
                f"relogin_session={token}; HttpOnly; Secure; SameSite=Lax; Path={PREFIX}; Max-Age=43200",
            )
            raw = b'{"ok":true}'
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if path == PREFIX + "/api/logout":
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                f"relogin_session=; HttpOnly; Secure; SameSite=Lax; Path={PREFIX}; Max-Age=0",
            )
            raw = b'{"ok":true}'
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(raw)
            return
        if not self.authorized():
            self.send_json(401, {"error": "需要登录"})
            return
        prefix = PREFIX + "/api/slots/"
        if path.startswith(prefix):
            vm_id = path[len(prefix) :]
            if not vm_id or "/" in vm_id or not vm_id.startswith("vm-"):
                self.send_json(400, {"error": "槽位编号不对"})
                return
            try:
                save_account(vm_id, body.get("email") or "", body.get("password") or "", body.get("totp") or "")
                if body.get("run"):
                    job = start_job(vm_id, "manual")
                    self.send_json(202, {"ok": True, "job_id": job["id"]})
                else:
                    self.send_json(200, {"ok": True})
            except Exception as exc:
                self.send_json(400, {"error": redact(exc)})
            return
        self.send_json(404, {"error": "not found"})


def main():
    os.makedirs(PROFILES, exist_ok=True)
    os.makedirs(SHOTS, exist_ok=True)
    host, port = LISTEN.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    print(f"listening {host}:{port}{PREFIX}/", flush=True)
    threading.Thread(target=sweep_loop, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
