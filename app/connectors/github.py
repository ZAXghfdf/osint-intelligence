"""GitHub REST API connector (public data; optional token raises rate limit)."""
from __future__ import annotations

import urllib.parse

from .base import BaseConnector, ConnectorError, ConnectorResult


class GithubConnector(BaseConnector):
    key = "github"
    name = "GitHub (حسابات ومستودعات عامة)"
    category = "code"
    input_types = ["username", "domain", "email"]
    env_key = "GITHUB_TOKEN"

    def _headers(self, ctx):
        token = ctx.get("secrets", {}).get("GITHUB_TOKEN")
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def test_connection(self, ctx):
        try:
            data, status, _ = self.http_get(
                "https://api.github.com/rate_limit", headers=self._headers(ctx)
            )
            remaining = data.get("resources", {}).get("core", {}).get("remaining")
            auth = "مفتاح مُهيأ" if ctx.get("secrets", {}).get("GITHUB_TOKEN") else "بدون مفتاح"
            return True, f"GitHub API متاح ({auth}) — الطلبات المتبقية: {remaining}"
        except ConnectorError as e:
            return False, str(e)

    def run(self, indicator_type, value, ctx):
        headers = self._headers(ctx)
        results: list[ConnectorResult] = []
        if indicator_type == "username":
            uname = value.lstrip("@")
            try:
                data, _, _ = self.http_get(
                    f"https://api.github.com/users/{urllib.parse.quote(uname)}", headers=headers
                )
            except ConnectorError as e:
                if "404" in str(e):
                    raise ConnectorError("لا يوجد حساب GitHub بهذا الاسم")
                raise
            if isinstance(data, dict) and data.get("login"):
                results.append(
                    ConnectorResult(
                        entity_type="username",
                        value=data["login"],
                        title="حساب GitHub عام",
                        url=data.get("html_url", ""),
                        confidence="direct",
                        verification_status="verified",
                        description=data.get("bio") or data.get("name") or "",
                        raw={"name": data.get("name"), "company": data.get("company"),
                             "location": data.get("location"), "public_repos": data.get("public_repos"),
                             "created_at": data.get("created_at")},
                        notes="بيانات ملف عام من GitHub API",
                    )
                )
        else:
            query = f"{value} in:name" if indicator_type == "domain" else f"{value}"
            url = "https://api.github.com/search/repositories?q=" + urllib.parse.quote(query) + "&per_page=15"
            data, _, _ = self.http_get(url, headers=headers)
            for item in (data.get("items", []) if isinstance(data, dict) else []):
                results.append(
                    ConnectorResult(
                        entity_type="url",
                        value=item.get("html_url", ""),
                        title=f"مستودع: {item.get('full_name')}",
                        url=item.get("html_url", ""),
                        confidence="probable",
                        verification_status="unverified",
                        description=item.get("description") or "",
                        raw={"language": item.get("language"), "stars": item.get("stargazers_count"),
                             "license": (item.get("license") or {}).get("spdx_id")},
                        notes="نتيجة بحث عامة — قد لا تتعلق بالهدف نفسه",
                    )
                )
        if not results:
            raise ConnectorError("لا نتائج من GitHub")
        return results
