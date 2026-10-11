"""HTTP headers connector — reads public response headers of a public host."""
from __future__ import annotations

import ssl
import urllib.request

from .. import security
from ..config import HTTP_TIMEOUT, HTTP_USER_AGENT
from .base import BaseConnector, ConnectorError, ConnectorResult

INTERESTING = [
    "server", "x-powered-by", "content-type", "strict-transport-security",
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "location", "via", "cf-ray",
]


class HttpHeadersConnector(BaseConnector):
    key = "http_headers"
    name = "HTTP Headers (رؤوس عامة)"
    category = "web"
    input_types = ["domain", "url"]

    def run(self, indicator_type, value, ctx):
        if indicator_type == "url":
            url = value
        else:
            url = f"https://{value}"
        ok, msg = security.safe_url(url)
        if not ok:
            raise ConnectorError(f"هدف محظور: {msg}")
        req = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT,
                                        context=ssl.create_default_context()) as resp:
                headers = dict(resp.headers)
                status = resp.status
                final_url = resp.geturl()
        except Exception as e:
            raise ConnectorError(f"تعذّر الاتصال بالهدف: {e}")
        results = []
        for h in INTERESTING:
            val = headers.get(h) or headers.get(h.title())
            if val:
                results.append(
                    ConnectorResult(
                        entity_type="service",
                        value=final_url,
                        title=f"ترويسة HTTP: {h}",
                        url=final_url,
                        confidence="direct",
                        verification_status="verified",
                        description=f"{h}: {val}",
                        raw={"header": h, "value": val, "status": status},
                        notes="رؤوس استجابة عامة من هدف عام",
                    )
                )
        if not results:
            raise ConnectorError("لم تُرجع الترويسات العامة أي بيانات")
        return results
