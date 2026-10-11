"""Authentication, sessions, role-based access control, and audit logging."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from . import database as db
from . import security
from .config import SESSION_TTL_SECONDS


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def create_user(username: str, password: str, role: str = "analyst",
                email: str = "", full_name: str = "") -> int:
    role_row = db.query_one("SELECT id FROM roles WHERE name=?", (role,))
    if not role_row:
        raise ValueError(f"دور غير معروف: {role}")
    cur = db.execute(
        """INSERT INTO users(username,email,full_name,password_hash,role_id)
           VALUES (?,?,?,?,?)""",
        (username.strip(), email, full_name, security.hash_password(password), role_row["id"]),
    )
    return cur.lastrowid


def authenticate(username: str, password: str) -> dict | None:
    row = db.query_one("SELECT * FROM users WHERE username=?", (username.strip(),))
    if not row or not row["is_active"]:
        return None
    if not security.verify_password(password, row["password_hash"]):
        return None
    return dict(row)


def get_user_context(user_id: int) -> dict | None:
    row = db.query_one(
        """SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id=u.role_id
           WHERE u.id=?""",
        (user_id,),
    )
    if not row:
        return None
    perms = db.query(
        """SELECT p.code FROM permissions p
           JOIN role_permissions rp ON rp.permission_id=p.id
           JOIN users u ON u.role_id=rp.role_id WHERE u.id=?""",
        (user_id,),
    )
    ctx = dict(row)
    ctx["permissions"] = sorted(p["code"] for p in perms)
    ctx.pop("password_hash", None)
    return ctx


def has_permission(ctx: dict, code: str) -> bool:
    return code in ctx.get("permissions", set())


def create_session(user_id: int, ip: str = "", user_agent: str = "") -> dict:
    sid = security.new_token(32)
    csrf = security.new_token(24)
    expires = (datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    db.execute(
        """INSERT INTO sessions(id,user_id,csrf_token,expires_at,ip,user_agent)
           VALUES (?,?,?,?,?,?)""",
        (sid, user_id, csrf, expires, ip, user_agent[:300]),
    )
    db.execute("UPDATE users SET last_login_at=? WHERE id=?", (_now(), user_id))
    return {"id": sid, "csrf_token": csrf, "expires_at": expires}


def get_session(sid: str) -> dict | None:
    if not sid:
        return None
    row = db.query_one("SELECT * FROM sessions WHERE id=?", (sid,))
    if not row:
        return None
    if row["expires_at"] < _now():
        db.execute("DELETE FROM sessions WHERE id=?", (sid,))
        return None
    return dict(row)


def destroy_session(sid: str) -> None:
    db.execute("DELETE FROM sessions WHERE id=?", (sid,))


def cleanup_sessions() -> None:
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))


def audit(user_id, action: str, entity_type: str = "", entity_id: str = "",
          details: dict | None = None, ip: str = "") -> None:
    # Never log secrets/passwords.
    safe = {}
    if details:
        for k, v in details.items():
            if any(s in k.lower() for s in ("password", "secret", "token", "key", "csrf")):
                safe[k] = "[redacted]"
            else:
                safe[k] = v
    db.execute(
        """INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details_json,ip)
           VALUES (?,?,?,?,?,?)""",
        (user_id, action, entity_type, str(entity_id), json.dumps(safe, ensure_ascii=False), ip),
    )
