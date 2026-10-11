"""Dataset management: parsing, preview, safe import, dedupe, internal search."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime

from . import database as db
from . import security
from .config import MAX_UPLOAD_BYTES
from .xlsx import read_xlsx

INDICATOR_TYPES = ["name", "username", "email", "domain", "phone", "ip", "url", "date", "other"]

# Auto-mapping hints by column name (Arabic and English).
MAPPING_HINTS = {
    "email": ["email", "e-mail", "mail", "بريد", "الايميل", "البريد"],
    "username": ["username", "user", "handle", "login", "اسم_المستخدم", "المعرف"],
    "name": ["name", "full_name", "fullname", "الاسم", "name_ar"],
    "domain": ["domain", "host", "site", "موقع", "نطاق"],
    "phone": ["phone", "mobile", "tel", "هاتف", "جوال", "الهاتف"],
    "ip": ["ip", "ip_address", "address"],
    "url": ["url", "link", "رابط"],
    "date": ["date", "created", "timestamp", "تاريخ"],
}


class ImportError_(Exception):
    pass


def _detect_encoding(head: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1256", "latin-1"):
        try:
            head.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "utf-8"


def parse_file(path, ext: str) -> tuple[list[dict], list[str]]:
    """Return (rows, field_names). Raises ImportError_ on failure."""
    ext = ext.lower()
    if ext == ".csv":
        raw = open(path, "rb").read()
        enc = _detect_encoding(raw[:4096])
        text = raw.decode(enc, "replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(r) for r in reader]
        fields = list(reader.fieldnames or (rows[0].keys() if rows else []))
        return rows, fields
    if ext in (".json", ".jsonl", ".ndjson"):
        text = open(path, "r", encoding="utf-8", errors="replace").read().strip()
        if ext == ".json":
            data = json.loads(text)
            if isinstance(data, list):
                rows = [r for r in data if isinstance(r, dict)]
            elif isinstance(data, dict):
                rows = [data]
            else:
                raise ImportError_("بنية JSON غير مدعومة")
        else:
            rows = []
            for line in text.splitlines():
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        rows.append(obj)
        fields = list(rows[0].keys()) if rows else []
        return rows, fields
    if ext == ".txt":
        rows = []
        for line in open(path, "r", encoding="utf-8", errors="replace"):
            v = line.strip()
            if v:
                rows.append({"value": v})
        return rows, ["value"]
    if ext == ".xlsx":
        rows = read_xlsx(path)
        fields = list(rows[0].keys()) if rows else []
        return rows, fields
    raise ImportError_(f"صيغة غير مدعومة: {ext}")


def suggest_mapping(fields: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    used = set()
    for f in fields:
        low = f.lower().strip()
        mapped = "other"
        for itype, hints in MAPPING_HINTS.items():
            if itype in used and itype != "name":
                continue
            if any(h in low for h in hints):
                mapped = itype
                used.add(itype)
                break
        mapping[f] = mapped
    return mapping


def preview(path, filename: str, limit: int = 25) -> dict:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    rows, fields = parse_file(path, ext)
    return {
        "fields": fields,
        "mapping": suggest_mapping(fields),
        "sample": rows[:limit],
        "total_rows": len(rows),
    }


def dedupe_hash(primary_type: str, primary_value: str, record: dict) -> str:
    if primary_type and primary_value:
        base = f"{primary_type}:{security.normalize_indicator(primary_value, primary_type)}"
    else:
        base = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _primary_indicator(mapping: dict, record: dict) -> tuple[str, str]:
    for itype in ["email", "username", "domain", "phone", "ip", "url", "name"]:
        for col, mt in mapping.items():
            if mt == itype and record.get(col):
                return itype, str(record[col])
    for col, val in record.items():
        if val:
            return "keyword", str(val)
    return "", ""


def import_file(dataset_id: int, job_id: int, path, filename: str, mapping: dict,
                version: int, user_id: int) -> dict:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    rows, _fields = parse_file(path, ext)

    conn = db.connect()
    cur = conn.cursor()
    cur.execute("BEGIN")
    report = {"total": len(rows), "imported": 0, "duplicate": 0, "rejected": 0, "errors": []}
    try:
        ver_cur = db.execute(
            "INSERT INTO dataset_versions(dataset_id,version,note) VALUES (?,?,?)",
            (dataset_id, version, f"استيراد {filename}"),
        )
        version_id = ver_cur.lastrowid
        for idx, record in enumerate(rows):
            itype, ivalue = _primary_indicator(mapping, record)
            norm = security.normalize_indicator(ivalue, itype) if ivalue else ""
            dh = dedupe_hash(itype, ivalue, record)
            dup = cur.execute(
                "SELECT id FROM dataset_records WHERE dataset_id=? AND dedupe_hash=?",
                (dataset_id, dh),
            ).fetchone()
            if dup:
                report["duplicate"] += 1
                continue
            if not record:
                report["rejected"] += 1
                continue
            cur.execute(
                """INSERT INTO dataset_records(dataset_id,job_id,version_id,record_json,
                     indicator_type,indicator_value,normalized_value,dedupe_hash)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (dataset_id, job_id, version_id, json.dumps(record, ensure_ascii=False),
                 itype, ivalue[:512], norm[:512], dh),
            )
            report["imported"] += 1
        # dataset fields metadata
        for col, mt in mapping.items():
            cur.execute(
                "INSERT INTO dataset_fields(dataset_id,field_name,mapped_type) VALUES (?,?,?)",
                (dataset_id, col, mt),
            )
        cur.execute(
            "UPDATE dataset_versions SET record_count=? WHERE id=?", (report["imported"], version_id)
        )
        cur.execute(
            "UPDATE datasets SET record_count=record_count+? WHERE id=?",
            (report["imported"], dataset_id),
        )
        cur.execute(
            """UPDATE dataset_import_jobs SET status='imported', total_rows=?, imported_rows=?,
               duplicate_rows=?, rejected_rows=?, version_id=?, report_json=?, finished_at=?
               WHERE id=?""",
            (report["total"], report["imported"], report["duplicate"], report["rejected"],
             version_id, json.dumps(report, ensure_ascii=False), _now(), job_id),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        db.execute(
            "UPDATE dataset_import_jobs SET status='failed', error=?, finished_at=? WHERE id=?",
            (str(e)[:500], _now(), job_id),
        )
        raise ImportError_(str(e))
    return report


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def next_version(dataset_id: int) -> int:
    row = db.query_one(
        "SELECT COALESCE(MAX(version),0) AS v FROM dataset_versions WHERE dataset_id=?",
        (dataset_id,),
    )
    return (row["v"] if row else 0) + 1


def list_datasets(user_ctx: dict) -> list[dict]:
    role = user_ctx.get("role")
    rows = db.query(
        """SELECT d.*, u.username AS created_by_name FROM datasets d
           LEFT JOIN users u ON u.id=d.created_by ORDER BY d.created_at DESC"""
    )
    out = []
    for r in rows:
        if not can_read(user_ctx, r["id"]):
            continue
        d = dict(r)
        d["can_write"] = can_write(user_ctx, r["id"])
        d["can_delete"] = can_delete(user_ctx, r["id"])
        out.append(d)
    return out


def can_read(user_ctx, dataset_id) -> bool:
    if user_ctx.get("role") == "admin":
        return True
    row = db.query_one(
        """SELECT dap.can_read FROM dataset_access_permissions dap
           JOIN roles r ON r.id=dap.role_id
           WHERE dap.dataset_id=? AND r.name=?""",
        (dataset_id, user_ctx.get("role")),
    )
    if row:
        return bool(row["can_read"])
    # Default: admin-see-all handled above; others must be granted explicitly.
    perm = db.query_one(
        "SELECT dataset_id FROM dataset_access_permissions WHERE dataset_id=?", (dataset_id,)
    )
    if not perm:
        # No ACL configured → datasets.read permission governs access.
        return "datasets.read" in user_ctx.get("permissions", set())
    return False


def can_write(user_ctx, dataset_id) -> bool:
    if user_ctx.get("role") == "admin":
        return True
    row = db.query_one(
        """SELECT dap.can_write FROM dataset_access_permissions dap
           JOIN roles r ON r.id=dap.role_id
           WHERE dap.dataset_id=? AND r.name=?""",
        (dataset_id, user_ctx.get("role")),
    )
    return bool(row["can_write"]) if row else "datasets.write" in user_ctx.get("permissions", set())


def can_delete(user_ctx, dataset_id) -> bool:
    if user_ctx.get("role") == "admin":
        return True
    row = db.query_one(
        """SELECT dap.can_delete FROM dataset_access_permissions dap
           JOIN roles r ON r.id=dap.role_id
           WHERE dap.dataset_id=? AND r.name=?""",
        (dataset_id, user_ctx.get("role")),
    )
    return bool(row["can_delete"]) if row else "datasets.delete" in user_ctx.get("permissions", set())


def search_records(dataset_id: int, query: str = "", page: int = 1, per_page: int = 25,
                   indicator_type: str = "") -> dict:
    where = ["dataset_id=?"]
    params: list = [dataset_id]
    if query:
        where.append("(normalized_value LIKE ? OR record_json LIKE ?)")
        params.extend([f"%{query.lower()}%", f"%{query}%"])
    if indicator_type:
        where.append("indicator_type=?")
        params.append(indicator_type)
    clause = " AND ".join(where)
    total = db.query_one(f"SELECT COUNT(*) AS c FROM dataset_records WHERE {clause}", tuple(params))["c"]
    offset = max(0, (page - 1) * per_page)
    rows = db.query(
        f"""SELECT * FROM dataset_records WHERE {clause}
            ORDER BY id DESC LIMIT ? OFFSET ?""",
        tuple(params + [per_page, offset]),
    )
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["record"] = json.loads(d["record_json"])
        except Exception:
            d["record"] = {}
        out.append(d)
    return {"total": total, "page": page, "per_page": per_page, "records": out}
