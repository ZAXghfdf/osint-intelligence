"""HTTP server bootstrap: request lifecycle, routing, static + SPA fallback."""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth
from . import config
from . import security
from .api import router
from .http import parse_request, serve_static, write_response, Response


class Handler(BaseHTTPRequestHandler):
    server_version = "OSINT-Intelligence"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Concise access log without sensitive data.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- verbs ----------------------------------------------------------
    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_OPTIONS(self):
        resp = Response(b"", 204)
        write_response(self, resp)

    # -- core -----------------------------------------------------------
    def _handle(self):
        try:
            req = parse_request(self)
        except Exception:
            write_response(self, Response.error("طلب غير صالح", 400))
            return

        # Load session + user context.
        sid = req.cookies.get(config.SESSION_COOKIE)
        if sid:
            sess = auth.get_session(sid)
            if sess:
                req.session = sess
                req.user = auth.get_user_context(sess["user_id"])

        handler, params = router.match(req.method, req.path)
        if handler is not None:
            bucket = security.rate_bucket_for(req.path, req.method)
            allowed, retry = security.rate_limit(bucket, req.client_ip)
            if not allowed:
                resp = Response.error(f"تجاوزت حد المعدل. أعد المحاولة بعد {retry} ثانية", 429)
                write_response(self, resp)
                return
            try:
                resp = handler(req, params or {})
            except Exception as e:  # noqa
                if config.ENV == "development":
                    import traceback
                    traceback.print_exc()
                resp = Response.error("خطأ داخلي في الخادم", 500)
            write_response(self, resp)
            return
        if params and params.get("__method_not_allowed__"):
            write_response(self, Response.error("الطريقة غير مدعومة", 405))
            return

        # Static assets
        if req.path.startswith("/api/"):
            write_response(self, Response.error("نقطة API غير موجودة", 404))
            return
        if req.path.startswith("/static/"):
            write_response(self, serve_static(config.STATIC_DIR, req.path[len("/static/"):]))
            return
        if req.path in ("/", "/index.html"):
            write_response(self, serve_static(config.STATIC_DIR, "index.html"))
            return
        # SPA fallback
        resp = serve_static(config.STATIC_DIR, req.path)
        if resp.status == 404:
            resp = serve_static(config.STATIC_DIR, "index.html")
        write_response(self, resp)


def serve(host: str = None, port: int = None):
    host = host or config.HOST
    port = port or config.PORT
    auth.cleanup_sessions()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"OSINT INTELLIGENCE يعمل على http://{host}:{port}")
    print(f"قاعدة البيانات: {config.DB_PATH}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nإيقاف الخادم...")
        httpd.shutdown()
