"""HTTP API routes for OSINT INTELLIGENCE."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

from . import auth
from . import dashboard
from . import database as db
from . import engine
from . import entity_resolution as er
from . import reports as reports_mod
from . import security
from . import tools_hub
from .config import (ALLOWED_UPLOAD_EXTS, BLOCKED_UPLOAD_EXTS, MAX_UPLOAD_BYTES,
                     SESSION_COOKIE, SESSION_TTL_SECONDS, UPLOAD_DIR,
                     get_source_secret, list_source_secret_keys,
                     load_authorized_targets, save_authorized_targets,
                     set_source_secret)
from .http import Response, Router
from .connectors import get_connector

router = Router()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _ctx(req):
    return req.user


def require(perm: str | None = None):
    def deco(fn):
        def wrapper(req, params):
            ctx = req.user
            if not ctx:
                return Response.error("يجب تسجيل الدخول", 401, "unauthorized")
            if perm and perm not in ctx.get("permissions", set()):
                return Response.error("لا تملك الصلاحية المطلوبة", 403, "forbidden")
            return fn(req, params)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


def csrf_ok(req) -> bool:
    if req.method in ("GET", "HEAD", "OPTIONS"):
        return True
    sess = req.session
    if not sess:
        return False
    token = req.headers.get("x-csrf-token", "")
    return bool(token) and token == sess["csrf_token"]


def guard(req) -> Response | None:
    if not csrf_ok(req):
        return Response.error("رمز CSRF غير صالح", 403, "csrf")
    return None


def _json_body(req) -> dict:
    return req.json() if req.content_type.startswith("application/json") else req.form()


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@router.post(r"/api/auth/login")
def login(req, params):
    data = _json_body(req)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return Response.error("اسم المستخدم وكلمة المرور مطلوبان", 400)
    user = auth.authenticate(username, password)
    if not user:
        auth.audit(None, "auth.login_failed", "user", username, ip=req.client_ip)
        return Response.error("بيانات الدخول غير صحيحة", 401)
    sess = auth.create_session(user["id"], req.client_ip, req.headers.get("user-agent", ""))
    ctx = auth.get_user_context(user["id"])
    resp = Response.json({"user": ctx, "csrf_token": sess["csrf_token"]})
    resp.set_cookie(SESSION_COOKIE, sess["id"], max_age=SESSION_TTL_SECONDS,
                    samesite="Lax")
    auth.audit(user["id"], "auth.login", "user", user["id"], ip=req.client_ip)
    return resp


@router.post(r"/api/auth/logout")
def logout(req, params):
    g = guard(req)
    if g:
        return g
    if req.session:
        auth.destroy_session(req.session["id"])
    resp = Response.json({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get(r"/api/auth/me")
def me(req, params):
    if not req.user:
        return Response.json({"authenticated": False})
    return Response.json({"authenticated": True, "user": req.user,
                          "csrf_token": req.session["csrf_token"]})


# --------------------------------------------------------------------------
# Dashboard / meta
# --------------------------------------------------------------------------
@router.get(r"/api/dashboard")
@require("search.read")
def get_dashboard(req, params):
    return Response.json(dashboard.stats())


@router.get(r"/api/meta")
def meta(req, params):
    return Response.json({
        "app": "OSINT INTELLIGENCE",
        "description": "منصة تحليل وربط المعلومات الرقمية مفتوحة المصدر",
        "authenticated": bool(req.user),
        "env": "development",
    })


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------
@router.get(r"/api/sources")
@require("search.read")
def list_sources(req, params):
    rows = [dict(r) for r in db.query("SELECT * FROM sources ORDER BY category, name")]
    configured = set(list_source_secret_keys())
    for r in rows:
        r["configured"] = (not r["requires_key"]) or (
            bool(r["env_key"]) and (r["env_key"] in configured
                                    or bool(get_source_secret(r["env_key"])))
        )
        r["input_types"] = json.loads(r["input_types"] or "[]")
    return Response.json({"sources": rows})


@router.post(r"/api/sources/(?P<key>[a-z0-9_]+)/toggle")
@require("sources.manage")
def toggle_source(req, params):
    g = guard(req)
    if g:
        return g
    row = db.query_one("SELECT * FROM sources WHERE key=?", (params["key"],))
    if not row:
        return Response.error("مصدر غير معروف", 404)
    newval = 0 if row["enabled"] else 1
    db.execute("UPDATE sources SET enabled=?, updated_at=datetime('now') WHERE key=?",
               (newval, params["key"]))
    auth.audit(req.user["id"], "source.toggle", "source", params["key"], {"enabled": newval})
    return Response.json({"ok": True, "enabled": newval})


@router.post(r"/api/sources/(?P<key>[a-z0-9_]+)/test")
@require("sources.manage")
def test_source(req, params):
    g = guard(req)
    if g:
        return g
    conn = get_connector(params["key"])
    if not conn:
        return Response.error("موصل غير معروف", 404)
    env_key = conn.env_key
    ctx = {"secrets": {env_key: get_source_secret(env_key)} if env_key else {}}
    ok, msg = conn.test_connection(ctx)
    db.execute("UPDATE sources SET status=?, last_error=? WHERE key=?",
               ("ok" if ok else "error", None if ok else msg, params["key"]))
    return Response.json({"ok": ok, "message": msg})


@router.post(r"/api/sources/(?P<key>[a-z0-9_]+)/secret")
@require("sources.manage")
def set_secret(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    value = data.get("value") or ""
    row = db.query_one("SELECT * FROM sources WHERE key=?", (params["key"],))
    if not row or not row["env_key"]:
        return Response.error("هذا المصدر لا يدعم مفتاح API", 400)
    if value:
        set_source_secret(row["env_key"], value)
        db.execute("UPDATE sources SET status='ok' WHERE key=?", (params["key"],))
    auth.audit(req.user["id"], "source.secret_set", "source", params["key"])
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------
@router.post(r"/api/search")
@require("search.run")
def create_search(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    raw = data.get("input") or ""
    if not raw.strip():
        return Response.error("أدخل مؤشر بحث واحدًا على الأقل", 400)
    source_keys = data.get("sources") or []
    scope = data.get("scope") or "both"
    forced = data.get("type") if data.get("type") not in (None, "", "auto") else None
    title = data.get("title") or ""
    search_id = engine.create_search(req.user["id"], title, raw, source_keys, scope, forced)
    return Response.json({"search_id": search_id})


@router.get(r"/api/search/(?P<search_id>\d+)")
@require("search.read")
def get_search(req, params):
    data = engine.get_search(int(params["search_id"]))
    if not data:
        return Response.error("عملية بحث غير موجودة", 404)
    return Response.json(data)


@router.post(r"/api/search/(?P<search_id>\d+)/cancel")
@require("search.run")
def cancel_search(req, params):
    g = guard(req)
    if g:
        return g
    engine.cancel_search(int(params["search_id"]))
    return Response.json({"ok": True})


@router.get(r"/api/searches")
@require("search.read")
def list_searches(req, params):
    if req.user["role"] == "admin":
        rows = db.query(
            """SELECT s.*, u.username FROM searches s LEFT JOIN users u ON u.id=s.user_id
               ORDER BY s.id DESC LIMIT 200""")
    else:
        rows = db.query(
            """SELECT s.*, u.username FROM searches s LEFT JOIN users u ON u.id=s.user_id
               WHERE s.user_id=? ORDER BY s.id DESC LIMIT 200""", (req.user["id"],))
    return Response.json({"searches": [dict(r) for r in rows]})


@router.delete(r"/api/search/(?P<search_id>\d+)")
@require("search.delete")
def delete_search(req, params):
    g = guard(req)
    if g:
        return g
    db.execute("DELETE FROM searches WHERE id=?", (int(params["search_id"]),))
    auth.audit(req.user["id"], "search.delete", "search", params["search_id"])
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Entities / graph
# --------------------------------------------------------------------------
@router.get(r"/api/entities/(?P<entity_id>\d+)")
@require("search.read")
def entity_details(req, params):
    d = er.node_details(int(params["entity_id"]))
    if not d:
        return Response.error("كيان غير موجود", 404)
    return Response.json(d)


@router.get(r"/api/graph")
@require("search.read")
def graph(req, params):
    search_id = req.q("search_id")
    if search_id:
        return Response.json(er.graph_for_search(int(search_id)))
    return Response.json(er.global_graph())


# --------------------------------------------------------------------------
# Datasets
# --------------------------------------------------------------------------
@router.get(r"/api/datasets")
@require("datasets.read")
def list_datasets(req, params):
    from . import datasets as ds
    return Response.json({"datasets": ds.list_datasets(req.user)})


@router.post(r"/api/datasets")
@require("datasets.write")
def create_dataset(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    name = (data.get("name") or "").strip()
    if not name:
        return Response.error("اسم مجموعة البيانات مطلوب", 400)
    existing = db.query_one("SELECT id FROM datasets WHERE name=?", (name,))
    if existing:
        return Response.error("توجد مجموعة بنفس الاسم", 409)
    cur = db.execute(
        """INSERT INTO datasets(name,description,source_name,source_url,purpose,license,
             acquired_at,created_by) VALUES (?,?,?,?,?,?,?,?)""",
        (name, data.get("description"), data.get("source_name"), data.get("source_url"),
         data.get("purpose"), data.get("license"), data.get("acquired_at"), req.user["id"]),
    )
    ds_id = cur.lastrowid
    db.execute(
        "INSERT INTO dataset_sources(dataset_id,source_name,source_url,license,acquired_at) VALUES (?,?,?,?,?)",
        (ds_id, data.get("source_name"), data.get("source_url"), data.get("license"),
         data.get("acquired_at")))
    auth.audit(req.user["id"], "dataset.create", "dataset", ds_id, {"name": name})
    return Response.json({"id": ds_id})


def _validate_upload(filename: str, data: bytes) -> tuple[bool, str]:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in BLOCKED_UPLOAD_EXTS:
        return False, "نوع الملف محظور (تنفيذي أو غير مسموح)"
    if ext not in ALLOWED_UPLOAD_EXTS:
        return False, f"صيغة غير مدعومة: {ext}"
    if len(data) > MAX_UPLOAD_BYTES:
        return False, "الملف أكبر من الحد الأقصى المسموح"
    head = data[:16]
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:2] == b"#!":
        return False, "محتوى الملف تنفيذي ومحظور"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return False, "محتوى الملف تنفيذي ومحظور"
    if ext == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    inner = "." + info.filename.rsplit(".", 1)[-1].lower() if "." in info.filename else ""
                    if inner in BLOCKED_UPLOAD_EXTS:
                        return False, f"ملف ZIP يحتوي على ملف محظور: {info.filename}"
        except zipfile.BadZipFile:
            return False, "ملف ZIP غير صالح"
    return True, ""


@router.post(r"/api/datasets/(?P<ds_id>\d+)/upload")
@require("datasets.write")
def upload_dataset(req, params):
    g = guard(req)
    if g:
        return g
    from . import datasets as ds
    ds_id = int(params["ds_id"])
    if not ds.can_write(req.user, ds_id):
        return Response.error("لا تملك صلاحية الكتابة على هذه المجموعة", 403)
    files = req.files()
    if not files:
        return Response.error("لم يتم إرسال أي ملف", 400)
    f = files[0]
    ok, msg = _validate_upload(f["filename"], f["data"])
    if not ok:
        return Response.error(msg, 400)
    stored = UPLOAD_DIR / f"{int(time.time())}_{Path(f['filename']).name}"
    stored.write_bytes(f["data"])
    ext = "." + f["filename"].rsplit(".", 1)[-1].lower() if "." in f["filename"] else ""
    try:
        prev = ds.preview(stored, f["filename"])
    except Exception as e:
        return Response.error(f"تعذّر قراءة الملف: {e}", 400)
    cur = db.execute(
        """INSERT INTO dataset_import_jobs(dataset_id,filename,file_type,size_bytes,
             stored_path,status,total_rows,created_by)
           VALUES (?,?,?,?,?, 'previewed', ?, ?)""",
        (ds_id, f["filename"], ext, len(f["data"]), str(stored), prev["total_rows"], req.user["id"]),
    )
    job_id = cur.lastrowid
    auth.audit(req.user["id"], "dataset.upload", "dataset", ds_id,
               {"filename": f["filename"], "size": len(f["data"])})
    return Response.json({"job_id": job_id, "preview": prev,
                          "size_bytes": len(f["data"])})


@router.post(r"/api/datasets/(?P<ds_id>\d+)/jobs/(?P<job_id>\d+)/import")
@require("datasets.write")
def import_dataset(req, params):
    g = guard(req)
    if g:
        return g
    from . import datasets as ds
    ds_id, job_id = int(params["ds_id"]), int(params["job_id"])
    if not ds.can_write(req.user, ds_id):
        return Response.error("لا تملك صلاحية الكتابة", 403)
    job = db.query_one("SELECT * FROM dataset_import_jobs WHERE id=? AND dataset_id=?",
                       (job_id, ds_id))
    if not job:
        return Response.error("مهمة استيراد غير موجودة", 404)
    data = _json_body(req)
    mapping = data.get("mapping") or {}
    if not mapping:
        return Response.error("حدّد مطابقة الأعمدة أولاً", 400)
    version = ds.next_version(ds_id)
    db.execute("UPDATE dataset_import_jobs SET status='importing', mapping_json=? WHERE id=?",
               (json.dumps(mapping, ensure_ascii=False), job_id))
    try:
        report = ds.import_file(ds_id, job_id, job["stored_path"], job["filename"],
                                mapping, version, req.user["id"])
    except Exception as e:
        return Response.error(f"فشل الاستيراد: {e}", 400)
    auth.audit(req.user["id"], "dataset.import", "dataset", ds_id,
               {"job_id": job_id, "report": report})
    return Response.json({"ok": True, "report": report})


@router.get(r"/api/datasets/(?P<ds_id>\d+)/records")
@require("datasets.read")
def dataset_records(req, params):
    from . import datasets as ds
    ds_id = int(params["ds_id"])
    if not ds.can_read(req.user, ds_id):
        return Response.error("لا تملك صلاحية قراءة هذه المجموعة", 403)
    page = int(req.q("page", "1") or 1)
    per_page = min(int(req.q("per_page", "25") or 25), 100)
    query = req.q("q", "") or ""
    itype = req.q("type", "") or ""
    return Response.json(ds.search_records(ds_id, query, page, per_page, itype))


@router.get(r"/api/datasets/(?P<ds_id>\d+)/jobs")
@require("datasets.read")
def dataset_jobs(req, params):
    from . import datasets as ds
    ds_id = int(params["ds_id"])
    if not ds.can_read(req.user, ds_id):
        return Response.error("لا تملك صلاحية", 403)
    rows = db.query(
        "SELECT * FROM dataset_import_jobs WHERE dataset_id=? ORDER BY id DESC", (ds_id,))
    return Response.json({"jobs": [dict(r) for r in rows]})


@router.delete(r"/api/datasets/(?P<ds_id>\d+)")
@require("datasets.delete")
def delete_dataset(req, params):
    g = guard(req)
    if g:
        return g
    from . import datasets as ds
    ds_id = int(params["ds_id"])
    if not ds.can_delete(req.user, ds_id):
        return Response.error("لا تملك صلاحية الحذف", 403)
    db.execute("DELETE FROM datasets WHERE id=?", (ds_id,))
    auth.audit(req.user["id"], "dataset.delete", "dataset", ds_id)
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Tools Hub
# --------------------------------------------------------------------------
@router.get(r"/api/tools")
@require("search.read")
def list_tools(req, params):
    return Response.json({"tools": tools_hub.list_tools()})


@router.post(r"/api/tools/refresh")
@require("tools.manage")
def refresh_tools(req, params):
    g = guard(req)
    if g:
        return g
    return Response.json({"results": tools_hub.refresh_installation_status()})


@router.post(r"/api/tools/run")
@require("tools.run")
def run_tool(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    try:
        result = tools_hub.run_task(
            req.user, data.get("tool"), data.get("target", ""),
            data.get("options") or {}, data.get("search_id"),
            data.get("timeout"),
        )
    except PermissionError as e:
        return Response.error(str(e), 403)
    except ValueError as e:
        return Response.error(str(e), 400)
    return Response.json(result)


@router.get(r"/api/tools/tasks")
@require("search.read")
def list_tool_tasks(req, params):
    return Response.json({"tasks": tools_hub.list_tasks()})


@router.get(r"/api/tools/tasks/(?P<task_id>\d+)")
@require("search.read")
def tool_task_details(req, params):
    d = tools_hub.task_details(int(params["task_id"]))
    if not d:
        return Response.error("مهمة غير موجودة", 404)
    return Response.json(d)


@router.get(r"/api/github/projects")
@require("search.read")
def github_projects(req, params):
    return Response.json({"projects": tools_hub.list_github_projects()})


@router.post(r"/api/github/discover")
@require("tools.manage")
def github_discover(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    query = (data.get("query") or "").strip()
    if not query:
        return Response.error("أدخل كلمة مفتاحية للبحث", 400)
    try:
        results = tools_hub.github_discover(query, data.get("category", ""),
                                            int(data.get("per_page", 10)))
    except ValueError as e:
        return Response.error(str(e), 400)
    auth.audit(req.user["id"], "github.discover", "github", query)
    return Response.json({"results": results})


@router.post(r"/api/github/projects")
@require("tools.manage")
def github_save(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    if not data.get("repo_full_name"):
        return Response.error("بيانات المشروع ناقصة", 400)
    pid = tools_hub.save_github_project(data, req.user["id"])
    return Response.json({"id": pid})


@router.post(r"/api/github/projects/(?P<pid>\d+)/review")
@require("tools.manage")
def github_review(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    tools_hub.review_github_project(int(params["pid"]), data.get("decision", ""),
                                    data.get("reason", ""), req.user)
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
@router.post(r"/api/reports")
@require("reports.create")
def create_report(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    try:
        result = reports_mod.build_report(int(data.get("search_id")), data.get("format", "json"),
                                          req.user, data.get("title", ""))
    except ValueError as e:
        return Response.error(str(e), 400)
    return Response.json({"id": result["id"], "filename": result["filename"],
                          "content_type": result["content_type"]})


@router.get(r"/api/reports")
@require("reports.create")
def list_reports(req, params):
    return Response.json({"reports": reports_mod.list_reports(req.user)})


@router.get(r"/api/reports/(?P<rid>\d+)/download")
@require("reports.create")
def download_report(req, params):
    row = db.query_one("SELECT * FROM reports WHERE id=?", (int(params["rid"]),))
    if not row:
        return Response.error("تقرير غير موجود", 404)
    if req.user["role"] != "admin" and row["user_id"] != req.user["id"]:
        return Response.error("لا تملك صلاحية", 403)
    path = Path(row["file_path"])
    if not path.exists():
        return Response.error("الملف غير موجود", 404)
    ctype = {"json": "application/json; charset=utf-8",
             "csv": "text/csv; charset=utf-8",
             "html": "text/html; charset=utf-8",
             "pdf": "text/html; charset=utf-8"}.get(row["format"], "application/octet-stream")
    resp = Response(path.read_bytes(), 200, ctype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{row["file_path"].split("/")[-1]}"'
    return resp


# --------------------------------------------------------------------------
# Admin: users, targets, audit
# --------------------------------------------------------------------------
@router.get(r"/api/users")
@require("users.manage")
def list_users(req, params):
    rows = db.query(
        """SELECT u.id,u.username,u.email,u.full_name,u.is_active,u.created_at,
                  u.last_login_at,r.name AS role
           FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id""")
    return Response.json({"users": [dict(r) for r in rows],
                          "roles": [dict(r) for r in db.query("SELECT name FROM roles")]})


@router.post(r"/api/users")
@require("users.manage")
def create_user(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "viewer"
    if len(password) < 8:
        return Response.error("كلمة المرور يجب أن تكون 8 أحرف على الأقل", 400)
    try:
        uid = auth.create_user(username, password, role, data.get("email", ""),
                               data.get("full_name", ""))
    except Exception as e:
        return Response.error(str(e), 400)
    auth.audit(req.user["id"], "user.create", "user", uid, {"role": role})
    return Response.json({"id": uid})


@router.get(r"/api/targets")
@require("tools.manage")
def get_targets(req, params):
    return Response.json({"targets": load_authorized_targets()})


@router.post(r"/api/targets")
@require("tools.manage")
def add_target(req, params):
    g = guard(req)
    if g:
        return g
    data = _json_body(req)
    targets = load_authorized_targets()
    for t in (data.get("targets") or []):
        t = t.strip()
        if t and t not in targets:
            targets.append(t)
    save_authorized_targets(targets)
    auth.audit(req.user["id"], "targets.update", "targets", "", {"count": len(targets)})
    return Response.json({"targets": targets})


@router.get(r"/api/audit")
@require("audit.read")
def audit_log(req, params):
    rows = db.query(
        """SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
           ORDER BY a.id DESC LIMIT 300""")
    return Response.json({"logs": [dict(r) for r in rows]})
