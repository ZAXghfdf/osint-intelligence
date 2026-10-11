"""Base connector abstraction and shared HTTP helper with SSRF protection."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from .. import security
from ..config import HTTP_TIMEOUT, HTTP_USER_AGENT


class ConnectorError(Exception):
    def __init__(self, message: str, *, unconfigured: bool = False):
        super().__init__(message)
        self.unconfigured = unconfigured


class ConnectorResult:
    """A single normalized finding produced by a connector."""

    def __init__(self, entity_type: str, value: str, title: str = "", url: str = "",
                 confidence: str = "probable", description: str = "",
                 verification_status: str = "unverified", raw: dict | None = None,
                 notes: str = ""):
        self.entity_type = entity_type
        self.value = value
        self.title = title
        self.url = url
        self.confidence = confidence  # direct|probable|weak|unverified
        self.description = description
        self.verification_status = verification_status
        self.raw = raw or {}
        self.notes = notes

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "title": self.title,
            "url": self.url,
            "confidence": self.confidence,
            "description": self.description,
            "verification_status": self.verification_status,
            "collected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "raw": self.raw,
            "notes": self.notes,
        }


class BaseConnector:
    key = "base"
    name = "Base"
    category = "web"
    input_types: list[str] = []
    requires_key = False
    env_key: str | None = None

    def run(self, indicator_type: str, value: str, ctx: dict) -> list[ConnectorResult]:
        raise NotImplementedError

    def test_connection(self, ctx: dict) -> tuple[bool, str]:
        return True, "ok"

    # ------------------------------------------------------------------
    def http_get(self, url: str, *, headers: dict | None = None, timeout: float = None,
                 accept_json: bool = True, method: str = "GET", data: bytes | None = None):
        ok, msg = security.safe_url(url)
        if not ok:
            raise ConnectorError(f"طلب محظور: {msg}")
        req_headers = {"User-Agent": HTTP_USER_AGENT, "Accept": "application/json, */*"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers, method=method, data=data)
        ctx_ssl = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT,
                                        context=ctx_ssl) as resp:
                raw = resp.read(5 * 1024 * 1024)
                ctype = resp.headers.get("Content-Type", "")
                if accept_json and "json" in ctype:
                    try:
                        return json.loads(raw.decode("utf-8", "replace")), resp.status, dict(resp.headers)
                    except json.JSONDecodeError:
                        return raw.decode("utf-8", "replace"), resp.status, dict(resp.headers)
                return raw.decode("utf-8", "replace"), resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode("utf-8", "replace") if e.fp else ""
            raise ConnectorError(f"HTTP {e.code}: {body[:200]}")
        except urllib.error.URLError as e:
            raise ConnectorError(f"فشل الاتصال: {e.reason}")
        except TimeoutError:
            raise ConnectorError("انتهت المهلة الزمنية للطلب")

    def http_status(self, url: str, *, timeout: float = None) -> tuple[int, dict]:
        ok, msg = security.safe_url(url)
        if not ok:
            raise ConnectorError(f"طلب محظور: {msg}")
        req = urllib.request.Request(
            url, headers={"User-Agent": HTTP_USER_AGENT}, method="HEAD"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}
        except Exception as e:
            raise ConnectorError(f"فشل الاتصال: {e}")
