"""RDAP connector for public domain/IP registration data (no API key)."""
from __future__ import annotations

from .base import BaseConnector, ConnectorError, ConnectorResult


class RdapConnector(BaseConnector):
    key = "rdap"
    name = "RDAP (تسجيل النطاقات)"
    category = "domain"
    input_types = ["domain", "ip"]

    def run(self, indicator_type, value, ctx):
        if indicator_type == "ip":
            url = f"https://rdap.org/ip/{value}"
            entity_type = "ip"
        else:
            url = f"https://rdap.org/domain/{value}"
            entity_type = "domain"
        try:
            data, status, _ = self.http_get(url)
        except ConnectorError as e:
            raise ConnectorError(f"تعذّر الوصول إلى RDAP: {e}")
        if not isinstance(data, dict):
            raise ConnectorError("استجابة RDAP غير صالحة")

        results: list[ConnectorResult] = []
        ldap = data.get("ldhName") or value
        handle = data.get("handle", "")
        results.append(
            ConnectorResult(
                entity_type=entity_type,
                value=str(ldap).lower(),
                title="بيانات تسجيل (RDAP)",
                url=url,
                confidence="direct",
                verification_status="verified",
                description=f"معرّف: {handle}",
                raw={"handle": handle, "status": data.get("status")},
                notes="بيانات تسجيل علنية وفق سياسة RDAP",
            )
        )
        for event in data.get("events", []) or []:
            results.append(
                ConnectorResult(
                    entity_type=entity_type,
                    value=str(ldap).lower(),
                    title=f"حدث تسجيل: {event.get('eventAction')}",
                    url=url,
                    confidence="direct",
                    verification_status="verified",
                    description=str(event.get("eventDate")),
                    raw=event,
                )
            )
        for ent in data.get("entities", []) or []:
            roles = ", ".join(ent.get("roles", []) or [])
            results.append(
                ConnectorResult(
                    entity_type="organization",
                    value=ent.get("handle", "unknown"),
                    title=f"جهة مسجّلة ({roles})",
                    url=url,
                    confidence="probable",
                    description=f"handle={ent.get('handle')} roles={roles}",
                    raw={"handle": ent.get("handle"), "roles": roles},
                    notes="قد تتضمن بيانات اتصال عامة",
                )
            )
        return results
