"""Wayback Machine CDX API connector (public archive, no API key)."""
from __future__ import annotations

import urllib.parse

from .base import BaseConnector, ConnectorError, ConnectorResult


class WaybackConnector(BaseConnector):
    key = "wayback"
    name = "Wayback Machine (أرشيف عام)"
    category = "web"
    input_types = ["url", "domain"]

    def run(self, indicator_type, value, ctx):
        target = value
        if indicator_type == "domain":
            target = value
        params = {
            "url": target + ("/*" if "*" not in target else ""),
            "output": "json",
            "limit": "40",
            "fl": "timestamp,original,statuscode,mimetype",
            "collapse": "urlkey",
        }
        url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
        try:
            data, _, _ = self.http_get(url, timeout=25)
        except ConnectorError as e:
            raise ConnectorError(f"تعذّر الوصول إلى أرشيف الويب: {e}")
        rows = data if isinstance(data, list) else []
        if len(rows) <= 1:
            raise ConnectorError("لا توجد لقطات مؤرشفة")
        header = rows[0]
        results: list[ConnectorResult] = []
        for row in rows[1:]:
            rec = dict(zip(header, row))
            ts = rec.get("timestamp", "")
            original = rec.get("original", "")
            snap = f"https://web.archive.org/web/{ts}/{original}"
            results.append(
                ConnectorResult(
                    entity_type="url",
                    value=original,
                    title="لقطة مؤرشفة",
                    url=snap,
                    confidence="direct",
                    verification_status="verified",
                    description=f"الحالة {rec.get('statuscode')} — {rec.get('mimetype')}",
                    raw=rec,
                    notes="أرشيف عام (Wayback Machine)",
                )
            )
        return results
