"""DNS connector via Cloudflare DNS-over-HTTPS (public, no API key)."""
from __future__ import annotations

import json
import urllib.parse

from .base import BaseConnector, ConnectorError, ConnectorResult

DOH = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class DnsDohConnector(BaseConnector):
    key = "dns_doh"
    name = "DNS (Cloudflare DoH)"
    category = "web"
    input_types = ["domain", "email"]

    def _resolve(self, name: str, rtype: str):
        url = f"{DOH}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
        data, _, _ = self.http_get(url, headers={"Accept": "application/dns-json"})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return []
        return data.get("Answer", []) if isinstance(data, dict) else []

    def run(self, indicator_type, value, ctx):
        results: list[ConnectorResult] = []
        name = value.split("@")[-1] if indicator_type == "email" else value
        for rtype in RECORD_TYPES:
            try:
                answers = self._resolve(name, rtype)
            except ConnectorError:
                continue
            for ans in answers:
                rdata = ans.get("data", "").strip('"')
                results.append(
                    ConnectorResult(
                        entity_type="domain",
                        value=name,
                        title=f"سجل DNS ({rtype})",
                        confidence="direct",
                        verification_status="verified",
                        description=f"{rtype} → {rdata}",
                        raw={"type": rtype, "data": rdata, "ttl": ans.get("TTL")},
                        notes="بيانات DNS عامة من Cloudflare DoH",
                    )
                )
        if not results:
            raise ConnectorError("لم يتم العثور على سجلات DNS عامة")
        return results
