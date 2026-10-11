"""Central configuration and secret store for OSINT INTELLIGENCE."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORT_DIR = DATA_DIR / "reports"
STATIC_DIR = BASE_DIR / "static"
DB_PATH = DATA_DIR / "osint.db"
SECRETS_PATH = DATA_DIR / "secrets.json"

for _d in (DATA_DIR, UPLOAD_DIR, EVIDENCE_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- Runtime settings (overridable via environment) ---
HOST = os.environ.get("OSINT_HOST", "127.0.0.1")
PORT = int(os.environ.get("OSINT_PORT", "8787"))
ENV = os.environ.get("OSINT_ENV", "development")

# Upload constraints
MAX_UPLOAD_BYTES = int(os.environ.get("OSINT_MAX_UPLOAD", str(32 * 1024 * 1024)))
ALLOWED_UPLOAD_EXTS = {
    ".csv", ".json", ".jsonl", ".ndjson", ".txt", ".xlsx", ".zip",
}
# Executable / dangerous content is never accepted as a dataset.
BLOCKED_UPLOAD_EXTS = {
    ".exe", ".dll", ".so", ".bat", ".cmd", ".com", ".msi", ".sh", ".bash",
    ".py", ".pl", ".rb", ".php", ".jar", ".app", ".apk", ".deb", ".rpm",
    ".bin", ".elf", ".scr", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".lnk", ".dmg", ".iso", ".img",
}

# Session
SESSION_TTL_SECONDS = int(os.environ.get("OSINT_SESSION_TTL", str(12 * 3600)))
SESSION_COOKIE = "osint_sid"

# Network / SSRF guard
HTTP_TIMEOUT = float(os.environ.get("OSINT_HTTP_TIMEOUT", "12"))
HTTP_USER_AGENT = os.environ.get(
    "OSINT_USER_AGENT",
    "OSINT-Intelligence/0.1 (+authorized-open-source-research)",
)
# Only public internet may be reached. No private / link-local / metadata ranges.
BLOCKED_NETWORKS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "::1/128",
    "fc00::/7", "fe80::/10",
]

# Tool execution
TOOL_MAX_TIMEOUT = int(os.environ.get("OSINT_TOOL_MAX_TIMEOUT", "120"))
TOOL_MAX_CONCURRENT = int(os.environ.get("OSINT_TOOL_MAX_CONCURRENT", "2"))
TOOL_ALLOWED_TARGETS_FILE = DATA_DIR / "authorized_targets.json"
TOOL_ALLOWED_TARGETS_FILE.touch(exist_ok=True)


def _load_secrets() -> dict:
    if SECRETS_PATH.exists():
        try:
            return json.loads(SECRETS_PATH.read_text("utf-8"))
        except Exception:
            return {}
    return {}


_APP_SECRET = os.environ.get("OSINT_APP_SECRET")


def get_app_secret() -> str:
    """Persistent application secret used to sign sessions."""
    global _APP_SECRET
    if _APP_SECRET:
        return _APP_SECRET
    secrets_data = _load_secrets()
    if not secrets_data.get("app_secret"):
        secrets_data["app_secret"] = secrets.token_urlsafe(48)
        _save_secrets(secrets_data)
    _APP_SECRET = secrets_data["app_secret"]
    return _APP_SECRET


def _save_secrets(data: dict) -> None:
    SECRETS_PATH.write_text(json.dumps(data, indent=2), "utf-8")
    try:
        os.chmod(SECRETS_PATH, 0o600)
    except OSError:
        pass


def get_source_secret(key: str) -> str | None:
    """API keys live in a server-side secret store, never in the frontend."""
    return _load_secrets().get("sources", {}).get(key) or os.environ.get(key)


def set_source_secret(key: str, value: str) -> None:
    data = _load_secrets()
    data.setdefault("sources", {})[key] = value
    _save_secrets(data)


def list_source_secret_keys() -> list[str]:
    return sorted(_load_secrets().get("sources", {}).keys())


def load_authorized_targets() -> list[str]:
    try:
        return json.loads(TOOL_ALLOWED_TARGETS_FILE.read_text("utf-8"))
    except Exception:
        return []


def save_authorized_targets(targets: list[str]) -> None:
    TOOL_ALLOWED_TARGETS_FILE.write_text(json.dumps(sorted(set(targets)), indent=2), "utf-8")
