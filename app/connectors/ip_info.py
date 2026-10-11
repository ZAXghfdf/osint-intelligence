"""ip-api.com connector for approximate public IP metadata (no API key)."""
from __future__ import annotations

from .base import BaseConnector, ConnectorError, ConnectorResult


class IpInfoConnector(BaseConnector):
    key = "ip_info"
    name = "ip-api.com (بيانات IP تقريبية)"
    category = "ip"
    input_types = ["ip"]

    def run(self, indicator_type, value, ctx):
        url = f"http://ip-api.com/json/{value}?fields=status,message,country,regionName,city,isp,org,as,reverse,query"
        try:
            data, _, _ = self.http_get(url)
        except ConnectorError as e:
            raise ConnectorError(f"تعذّر الوصول إلى خدمة IP: {e}")
        if not isinstance(data, dict) or data.get("status") != "success":
            raise ConnectorError(data.get("message", "بيانات IP غير متاحة") if isinstance(data, dict) else "استجابة غير صالحة")
        results = [
            ConnectorResult(
                entity_type="ip",
                value=data.get("query", value),
                title="بيانات IP تقريبية",
                url=f"https://ip-api.com/#{value}",
                confidence="probable",
                verification_status="unverified",
                description=(f"ISP: {data.get('isp')} | ASN: {data.get('as')} | "
                             f"الدولة: {data.get('country')}"),
                raw=data,
                notes="الموقع الجغرافي تقريبي ولا يمثل موقع شخص",
            )
        ]
        if data.get("as"):
            results.append(
                ConnectorResult(
                    entity_type="organization",
                    value=data.get("org") or data.get("isp") or "unknown",
                    title="مزود الشبكة / ASN",
                    confidence="probable",
                    description=data.get("as", ""),
                    raw={"as": data.get("as"), "isp": data.get("isp"), "org": data.get("org")},
                )
            )
        return results
