"""Security utilities: password hashing, input validation, SSRF guard, headers."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
from urllib.parse import urlparse

from . import config

PBKDF2_ROUNDS = 200_000


# --------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256). Passwords are never stored in clear.
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def new_token(n: int = 32) -> str:
    return secrets.token_urlsafe(n)


# --------------------------------------------------------------------------
# Indicator validation
# --------------------------------------------------------------------------
RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$")
RE_USERNAME = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")
RE_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
RE_PHONE = re.compile(r"^\+?[0-9 ()\-\.]{7,20}$")


def _valid_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return None


def detect_indicator_type(value: str) -> str:
    v = value.strip()
    if not v:
        return "unknown"
    if RE_EMAIL.match(v):
        return "email"
    if RE_SHA256.match(v):
        return "hash"
    if _valid_ip(v):
        return "ip"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if v.startswith("@"):
        return "username"
    if RE_PHONE.match(v) and any(ch.isdigit() for ch in v) and not RE_DOMAIN.match(v):
        return "phone"
    if RE_DOMAIN.match(v):
        return "domain"
    if RE_USERNAME.match(v):
        return "username"
    return "keyword"


def normalize_indicator(value: str, itype: str) -> str:
    v = value.strip()
    if itype == "email":
        return v.lower()
    if itype == "domain":
        return v.lower().lstrip(".")
    if itype == "username":
        return v.lstrip("@").lower()
    if itype == "url":
        try:
            u = urlparse(v)
            return f"{u.scheme.lower()}://{u.netloc.lower()}{u.path.rstrip('/')}"
        except Exception:
            return v.lower()
    if itype == "phone":
        return re.sub(r"[^\d+]", "", v)
    return v.lower()


def validate_indicator(value: str, itype: str) -> tuple[bool, str]:
    v = value.strip()
    if itype == "email":
        return (bool(RE_EMAIL.match(v)), "صيغة البريد الإلكتروني غير صحيحة")
    if itype == "domain":
        return (bool(RE_DOMAIN.match(v)), "اسم النطاق غير صالح")
    if itype == "ip":
        try:
            ipaddress.ip_address(v)
            return True, ""
        except ValueError:
            return False, "عنوان IP غير صالح"
    if itype == "username":
        return (bool(RE_USERNAME.match(v.lstrip("@"))), "اسم المستخدم غير صالح")
    if itype == "url":
        return (bool(re.match(r"^https?://", v)), "الرابط يجب أن يبدأ بـ http أو https")
    if itype == "phone":
        return (bool(RE_PHONE.match(v)), "صيغة رقم الهاتف غير صالحة")
    return True, ""


# --------------------------------------------------------------------------
# SSRF guard — block private, loopback, link-local and metadata ranges.
# --------------------------------------------------------------------------
def is_public_host(host: str) -> tuple[bool, str]:
    host = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        return _ip_is_public(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "تعذّر تحليل اسم المضيف"
    if not infos:
        return False, "لا توجد عناوين للمضيف"
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False, "عنوان غير صالح"
        ok, msg = _ip_is_public(ip)
        if not ok:
            return False, msg
    return True, ""


def _ip_is_public(ip: ipaddress._BaseAddress) -> tuple[bool, str]:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False, "العنوان ضمن نطاق داخلي أو محجوز"
    if ip.is_multicast or ip.is_unspecified:
        return False, "عنوان غير مسموح"
    # Cloud metadata
    if str(ip) == "169.254.169.254":
        return False, "عناوين Metadata السحابية محظورة"
    return True, ""


def safe_url(url: str) -> tuple[bool, str]:
    try:
        u = urlparse(url)
    except Exception:
        return False, "رابط غير صالح"
    if u.scheme not in ("http", "https"):
        return False, "يُسمح ببروتوكول http/https فقط"
    if not u.hostname:
        return False, "المضيف مفقود"
    return is_public_host(u.hostname)


# --------------------------------------------------------------------------
# CSV formula-injection protection for exports
# --------------------------------------------------------------------------
_DANGEROUS_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value) -> str:
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in _DANGEROUS_PREFIX:
        return "'" + s
    return s


# --------------------------------------------------------------------------
# Response security headers
# --------------------------------------------------------------------------
def security_headers() -> dict:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        ),
    }


# --------------------------------------------------------------------------
# In-memory rate limiting (per client + bucket). Token-bucket style.
# --------------------------------------------------------------------------
import threading as _threading
import time as _time

_rl_lock = _threading.Lock()
_rl_buckets: dict[str, tuple[float, float]] = {}
RATE_LIMITS = {
    "login": (10, 60.0),      # 10 requests / 60s
    "search": (30, 60.0),
    "tool": (20, 60.0),
    "upload": (15, 60.0),
    "default": (240, 60.0),
}


def rate_limit(bucket: str, key: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds)."""
    limit, window = RATE_LIMITS.get(bucket, RATE_LIMITS["default"])
    now = _time.monotonic()
    ident = f"{bucket}:{key}"
    with _rl_lock:
        tokens, last = _rl_buckets.get(ident, (float(limit), now))
        tokens = min(limit, tokens + (now - last) * (limit / window))
        if tokens < 1:
            retry = int(window - (now - last)) or 1
            _rl_buckets[ident] = (tokens, now)
            return False, retry
        _rl_buckets[ident] = (tokens - 1, now)
        if len(_rl_buckets) > 5000:
            _rl_buckets.clear()
        return True, 0


def rate_bucket_for(path: str, method: str) -> str:
    if path == "/api/auth/login":
        return "login"
    if path == "/api/search" and method == "POST":
        return "search"
    if path.startswith("/api/tools/run"):
        return "tool"
    if "/upload" in path or path.startswith("/api/datasets"):
        return "upload"
    return "default"
