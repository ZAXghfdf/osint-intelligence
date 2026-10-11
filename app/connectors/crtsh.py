"""crt.sh certificate transparency connector (public, no API key)."""
from __future__ import annotations

import json

from .base import BaseConnector, ConnectorError, ConnectorResult


class CrtshConnector(BaseConnector):
    key = "crt_sh"
    name = "crt.sh (شهادات رقمية)"
    category = "domain"
    input_types = ["domain"]

    def run(self, indicator_type, value, ctx):
        url = f"https://crt.sh/?q=%25.{value}&output=json"
        try:
            data, _, _ = self.http_get(url, timeout=25)
        except ConnectorError as e:
            raise ConnectorError(f"تعذّر الوصول إلى crt.sh: {e}")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                raise ConnectorError("استجابة crt.sh غير صالحة")
        seen = set()
        results: list[ConnectorResult] = []
        for entry in data if isinstance(data, list) else []:
            names = str(entry.get("name_value", "")).split("\n")
            issuer = entry.get("issuer_name", "")
            for n in names:
                n = n.strip().lower()
                if not n or n in seen:
                    continue
                seen.add(n)
                results.append(
                    ConnectorResult(
                        entity_type="domain",
                        value=n,
                        title="نطاق فرعي في سجل الشهادات",
                        url=f"https://crt.sh/?q={n}",
                        confidence="direct",
                        verification_status="verified",
                        description=f"صادر عن: {issuer}",
                        raw={"common_name": entry.get("common_name"),
                             "issuer": issuer, "not_before": entry.get("not_before")},
                        notes="سجل الشفافية للشهادات الرقمية (عام)",
                    )
                )
                if len(results) >= 100:
                    break
            if len(results) >= 100:
                break
        if not results:
            raise ConnectorError("لا توجد شهادات مسجّلة لهذا النطاق")
        return results
