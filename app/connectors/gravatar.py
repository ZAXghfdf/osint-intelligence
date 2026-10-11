"""Gravatar connector — verifies whether an avatar exists for an email hash."""
from __future__ import annotations

import hashlib

from .base import BaseConnector, ConnectorError, ConnectorResult


class GravatarConnector(BaseConnector):
    key = "gravatar"
    name = "Gravatar (تحقق بصمة بريد)"
    category = "email"
    input_types = ["email"]

    def run(self, indicator_type, value, ctx):
        email = value.strip().lower()
        h = hashlib.md5(email.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        try:
            status, _ = self.http_status(url)
        except ConnectorError as e:
            raise ConnectorError(f"تعذّر الوصول إلى Gravatar: {e}")
        if status == 200:
            return [
                ConnectorResult(
                    entity_type="email",
                    value=email,
                    title="صورة Gravatar مرتبطة بالبريد",
                    url=f"https://www.gravatar.com/avatar/{h}",
                    confidence="probable",
                    verification_status="unverified",
                    description="يوجد ملف Gravatar عام لهذا البريد (قد يدعم وجود حساب)",
                    raw={"md5": h, "http_status": status},
                    notes="وجود Gravatar مؤشر محتمل وليس تأكيدًا لهوية",
                )
            ]
        raise ConnectorError("لا يوجد Gravatar مرتبط بهذا البريد")
