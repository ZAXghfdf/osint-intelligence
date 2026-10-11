"""Minimal HTTP framework built on the standard library.

Provides request parsing (query, JSON, urlencoded, multipart/file uploads),
responses, cookie handling, routing and static file serving. No third-party
dependencies so it runs reliably on Termux/Android.
"""
from __future__ import annotations

import io
import json
import mimetypes
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import security


class Request:
    def __init__(self, method, path, query, headers, body: bytes, client_ip):
        self.method = method
        self.path = path
        self.raw_path = path
        self.query = query  # dict[str, list[str]]
        self.headers = headers
        self.body = body
        self.client_ip = client_ip
        self._json = None
        self._form = None
        self._files = None
        self.params: dict = {}
        self.user = None
        self.session = None

    # -- query -----------------------------------------------------------
    def q(self, name, default=None):
        vals = self.query.get(name)
        return vals[0] if vals else default

    # -- cookies ---------------------------------------------------------
    @property
    def cookies(self) -> dict:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("cookie", ""))
        except Exception:
            return {}
        return {k: m.value for k, m in cookie.items()}

    # -- body parsers ----------------------------------------------------
    def json(self) -> dict:
        if self._json is None:
            if not self.body:
                self._json = {}
            else:
                try:
                    self._json = json.loads(self.body.decode("utf-8"))
                except Exception:
                    self._json = {}
        return self._json

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    def form(self) -> dict:
        if self._form is not None:
            return self._form
        self._parse_body()
        return self._form

    def files(self) -> list[dict]:
        if self._files is not None:
            return self._files
        self._parse_body()
        return self._files

    def _parse_body(self):
        self._form = {}
        self._files = []
        ctype = self.content_type
        if ctype.startswith("application/x-www-form-urlencoded"):
            data = parse_qs(self.body.decode("utf-8", "replace"), keep_blank_values=True)
            self._form = {k: v[0] for k, v in data.items()}
        elif ctype.startswith("multipart/form-data"):
            self._parse_multipart(ctype)
        elif ctype.startswith("application/json"):
            self._form = self.json()

    def _parse_multipart(self, ctype: str):
        m = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", ctype)
        if not m:
            return
        boundary = (m.group(1) or m.group(2)).strip()
        delim = b"--" + boundary.encode("utf-8")
        parts = self.body.split(delim)
        for part in parts[1:]:
            if part in (b"--", b"--\r\n", b"", b"\r\n"):
                continue
            part = part.lstrip(b"\r\n")
            if part.endswith(b"\r\n"):
                part = part[:-2]
            if b"\r\n\r\n" not in part:
                continue
            raw_headers, content = part.split(b"\r\n\r\n", 1)
            headers = {}
            for line in raw_headers.split(b"\r\n"):
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
            disp = headers.get("content-disposition", "")
            name_m = re.search(r'name="([^"]*)"', disp)
            file_m = re.search(r'filename="([^"]*)"', disp)
            field = name_m.group(1) if name_m else ""
            if file_m is not None:
                self._files.append(
                    {
                        "field": field,
                        "filename": file_m.group(1),
                        "content_type": headers.get("content-type", "application/octet-stream"),
                        "data": content,
                    }
                )
            else:
                self._form[field] = content.decode("utf-8", "replace")


class Response:
    def __init__(self, body=b"", status=200, content_type="text/plain; charset=utf-8",
                 headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        self.status = status
        self.content_type = content_type
        self.headers = headers or {}
        self.cookies: list[tuple] = []

    def set_cookie(self, name, value, max_age=None, httponly=True, samesite="Lax",
                   path="/", secure=False):
        parts = [f"{name}={value}", f"Path={path}", f"SameSite={samesite}"]
        if httponly:
            parts.append("HttpOnly")
        if secure:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        self.cookies.append(("Set-Cookie", "; ".join(parts)))

    def delete_cookie(self, name, path="/"):
        self.cookies.append(("Set-Cookie", f"{name}=; Path={path}; Max-Age=0; HttpOnly"))

    @classmethod
    def json(cls, data, status=200):
        return cls(json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   status, "application/json; charset=utf-8")

    @classmethod
    def error(cls, message, status=400, code=None):
        return cls.json({"error": message, "code": code}, status=status)

    @classmethod
    def redirect(cls, location, status=302):
        return cls(b"", status, "text/plain", {"Location": location})


class Router:
    def __init__(self):
        self.routes: list[tuple[str, re.Pattern, callable]] = []

    def add(self, method, pattern, handler):
        regex = re.compile("^" + pattern + "$")
        self.routes.append((method.upper(), regex, handler))

    def route(self, method, pattern):
        def deco(fn):
            self.add(method, pattern, fn)
            return fn
        return deco

    def get(self, pattern):
        return self.route("GET", pattern)

    def post(self, pattern):
        return self.route("POST", pattern)

    def put(self, pattern):
        return self.route("PUT", pattern)

    def delete(self, pattern):
        return self.route("DELETE", pattern)

    def match(self, method, path):
        path_matched = False
        for m, regex, handler in self.routes:
            match = regex.match(path)
            if match:
                path_matched = True
                if m == method.upper() or m == "ANY":
                    return handler, match.groupdict()
        if path_matched:
            return None, {"__method_not_allowed__": True}
        return None, None


def parse_request(handler) -> Request:
    parsed = urlparse(handler.path)
    path = unquote(parsed.path)
    query = parse_qs(parsed.query, keep_blank_values=True)
    length = int(handler.headers.get("Content-Length") or 0)
    body = handler.rfile.read(length) if length else b""
    client_ip = handler.client_address[0] if handler.client_address else ""
    req = Request(handler.command, path, query, handler.headers, body, client_ip)
    return req


def write_response(handler, resp: Response):
    if resp.status in (301, 302, 303, 307, 308):
        handler.send_response(resp.status)
    else:
        handler.send_response(resp.status)
    handler.send_header("Content-Type", resp.content_type)
    handler.send_header("Content-Length", str(len(resp.body)))
    for k, v in security.security_headers().items():
        handler.send_header(k, v)
    for k, v in resp.headers.items():
        handler.send_header(k, v)
    for k, v in resp.cookies:
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(resp.body)


def serve_static(static_dir, path: str) -> Response:
    # Prevent path traversal.
    safe = path.replace("\\", "/").lstrip("/")
    target = (static_dir / safe).resolve()
    if not str(target).startswith(str(static_dir.resolve())):
        return Response.error("forbidden", 403)
    if target.is_dir():
        target = target / "index.html"
    if not target.exists() or not target.is_file():
        return Response.error("not found", 404)
    ctype, _ = mimetypes.guess_type(str(target))
    ctype = ctype or "application/octet-stream"
    if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
        ctype += "; charset=utf-8"
    return Response(target.read_bytes(), 200, ctype)
