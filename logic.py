"""Pure helpers for the relogin sidecar. No browser and no network."""

import base64
import hashlib
import hmac
import re
import time
import urllib.parse

WINDOW_S = 6 * 3600
AUTO_LIMIT = 2
MANUAL_LIMIT = 5

PASSWORD_HINT = re.compile(
    r"password|mot de passe|passwort|contraseñ|senha|парол|密码|パスワード|암호|"
    r"wachtwoord|hasło|heslo|jelszó|parola|lösenord|salasana|passord",
    re.IGNORECASE,
)
SHOW_HINT = re.compile(r"show|afficher|mostrar|anzeigen|显示|表示|toggle", re.IGNORECASE)
PHONE_HINT = re.compile(
    r"phone|téléphone|telefon|teléfono|手机|電話|telefone|numer",
    re.IGNORECASE,
)
AUTH_HINT = re.compile(
    r"authenticator|authentificateur|验证器|认证器|aplicativo de autenticação|"
    r"authentication app|app d'authentification",
    re.IGNORECASE,
)
HUMAN_HINT = re.compile(
    r"verify you are human|just a moment|cf-challenge|cloudflare|人机验证|vérifiez que vous",
    re.IGNORECASE,
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}")
KEY_RE = re.compile(r"sk-[A-Za-z0-9_\-]{10,}")


def redact(text):
    text = "" if text is None else str(text)
    text = JWT_RE.sub("[jwt]", text)
    text = KEY_RE.sub("[key]", text)
    return text[:300]


def email_hash(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]


def is_callback_url(url):
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if host not in {"localhost", "127.0.0.1"}:
        return False
    if parsed.port != 1455:
        return False
    query = parsed.query or ""
    return "callback" in (parsed.path or "") or "code=" in query


def parse_proxy_uri(uri):
    """Turn a slot proxy URI into a Playwright HTTP proxy dict.

    Firefox cannot authenticate SOCKS5, and these Webshare endpoints accept
    HTTP on the same host:port with the same user and password.
    """
    if not uri or "://" not in uri:
        raise ValueError("proxy uri missing")
    rest = uri.split("://", 1)[1]
    if "@" not in rest:
        raise ValueError("proxy uri has no credentials")
    cred, hostport = rest.rsplit("@", 1)
    if ":" not in cred or not hostport:
        raise ValueError("proxy uri is malformed")
    user, password = cred.split(":", 1)
    user = urllib.parse.unquote(user)
    password = urllib.parse.unquote(password)
    return {"server": "http://" + hostport, "username": user, "password": password}


def normalize_totp_secret(secret):
    raw = re.sub(r"[\s\-]", "", secret or "").upper()
    if not raw or not re.fullmatch(r"[A-Z2-7]+=*", raw):
        raise ValueError("totp secret is not base32")
    pad = "=" * ((8 - len(raw) % 8) % 8)
    base64.b32decode(raw + pad, casefold=True)
    return raw


def totp_code(secret, now=None):
    raw = normalize_totp_secret(secret)
    pad = "=" * ((8 - len(raw) % 8) % 8)
    key = base64.b32decode(raw + pad, casefold=True)
    moment = time.time() if now is None else now
    remain = 30 - (moment % 30)
    if remain < 5:
        moment += remain + 1
    counter = int(moment) // 30
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


def fresh_events(events, now):
    return [item for item in events if now - item.get("t", 0) < WINDOW_S]


def allow_attempt(events, now, kind):
    fresh = fresh_events(events, now)
    if kind == "auto":
        used = sum(1 for item in fresh if item.get("kind") == "auto")
        return used < AUTO_LIMIT, fresh
    return len(fresh) < MANUAL_LIMIT, fresh


def duplicate_slot(email, vm_id, panel_emails, saved_emails):
    """Return another slot id that already uses this email, or None."""
    want = (email or "").strip().lower()
    if not want:
        return None
    ids = set(panel_emails) | set(saved_emails)
    for other in sorted(ids):
        if other == vm_id:
            continue
        panel = (panel_emails.get(other) or "").strip().lower()
        saved = (saved_emails.get(other) or "").strip().lower()
        if want == panel or want == saved:
            return other
    return None


def should_restore_previous(was_running, exchanged):
    """Start the slot again when login failed before a new token was written."""
    return bool(was_running) and not exchanged
