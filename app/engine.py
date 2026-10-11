"""OSINT Search Engine — orchestrates connectors, dedupes, scores and persists."""
from __future__ import annotations

import concurrent.futures
import json
import threading
from datetime import datetime

from . import auth as _auth
from . import database as db
from . import entity_resolution as er
from . import security
from .connectors import ConnectorError, connectors_for, get_connector
from .config import get_source_secret

_lock = threading.Lock()
_cancel: set[int] = set()
_running: dict[int, concurrent.futures.Executor] = {}


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------
def split_inputs(raw: str) -> list[str]:
    parts = []
    for line in (raw or "").replace(",", "\n").splitlines():
        v = line.strip()
        if v:
            parts.append(v)
    return parts


def parse_inputs(raw_values: list[str], forced_type: str | None = None):
    parsed = []
    for v in raw_values:
        itype = forced_type if forced_type and forced_type != "auto" else security.detect_indicator_type(v)
        valid, msg = security.validate_indicator(v, itype)
        parsed.append({
            "indicator_type": itype,
            "value": v,
            "normalized_value": security.normalize_indicator(v, itype),
            "valid": 1 if valid else 0,
            "error": "" if valid else msg,
        })
    return parsed


# --------------------------------------------------------------------------
# Search lifecycle
# --------------------------------------------------------------------------
def create_search(user_id: int, title: str, raw_input: str, source_keys: list[str],
                  scope: str = "both", forced_type: str | None = None) -> int:
    values = split_inputs(raw_input)
    parsed = parse_inputs(values, forced_type)
    summary = "; ".join(f"{p['indicator_type']}:{p['value']}" for p in parsed)[:500]
    cur = db.execute(
        """INSERT INTO searches(user_id,title,status,scope,input_summary)
           VALUES (?,?,?,?,?)""",
        (user_id, title or (values[0] if values else "بحث"), "running", scope, summary),
    )
    search_id = cur.lastrowid
    for p in parsed:
        db.execute(
            """INSERT INTO search_queries(search_id,indicator_type,value,normalized_value,valid)
               VALUES (?,?,?,?,?)""",
            (search_id, p["indicator_type"], p["value"], p["normalized_value"], p["valid"]),
        )
    _auth.audit(user_id, "search.create", "search", search_id,
                 {"inputs": summary, "scope": scope, "sources": source_keys})
    run_search_async(search_id, source_keys, scope)
    return search_id


def run_search_async(search_id: int, source_keys: list[str], scope: str) -> None:
    t = threading.Thread(target=_run_search, args=(search_id, source_keys, scope), daemon=True)
    t.start()


def _run_search(search_id: int, source_keys: list[str], scope: str) -> None:
    queries = db.query("SELECT * FROM search_queries WHERE search_id=?", (search_id,))
    valid_queries = [dict(q) for q in queries if q["valid"]]
    if not valid_queries:
        db.execute("UPDATE searches SET status='failed', completed_at=? WHERE id=?",
                   (_now(), search_id))
        return

    total_findings = 0
    needs_review = 0
    any_ok = False

    # Internal dataset search first (fast, local).
    if scope in ("internal", "both"):
        internal = search_datasets(valid_queries)
        total_findings += _store_dataset_findings(search_id, internal)

    if scope in ("external", "both"):
        runnable, skipped = _resolve_sources(valid_queries, source_keys)
        # Record skipped/unconfigured sources so they are visible.
        for key, reason in skipped:
            db.execute(
                """INSERT INTO source_runs(search_id,source_key,status,error,finished_at)
                   VALUES (?,?,?,?,?)""",
                (search_id, key, reason[0], reason[1], _now()),
            )
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
        with _lock:
            _running[search_id] = executor
        futures = {}
        for conn, query in runnable:
            futures[executor.submit(_run_connector, conn, query, search_id)] = (conn, query)
        for fut in concurrent.futures.as_completed(futures):
            try:
                ok, count, review = fut.result()
            except Exception:
                ok, count, review = False, 0, 0
            if ok:
                any_ok = True
            total_findings += count
            needs_review += review
            if search_id in _cancel:
                break
        executor.shutdown(wait=False)
        with _lock:
            _running.pop(search_id, None)

    cancelled = search_id in _cancel
    with _lock:
        _cancel.discard(search_id)
    if cancelled:
        status = "cancelled"
    elif any_ok or total_findings > 0:
        status = "completed"
    else:
        status = "failed"
    db.execute(
        """UPDATE searches SET status=?, result_count=?, needs_review=?, completed_at=?
           WHERE id=?""",
        (status, total_findings, needs_review, _now(), search_id),
    )


def _resolve_sources(queries, source_keys):
    """Return (runnable[(connector, query)], skipped[(key, (status,reason))])."""
    wanted_types = {q["indicator_type"] for q in queries}
    runnable = []
    skipped = []
    if source_keys:
        chosen = source_keys
    else:
        chosen = [s["key"] for s in db.query("SELECT key FROM sources")]
    for key in chosen:
        src = db.query_one("SELECT * FROM sources WHERE key=?", (key,))
        conn = get_connector(key)
        if not src or not conn:
            skipped.append((key, ("unconfigured", "الموصل غير معروف")))
            continue
        if not src["enabled"]:
            skipped.append((key, ("unconfigured", "الموصل معطّل")))
            continue
        if src["requires_key"] and src["env_key"] and not get_source_secret(src["env_key"]):
            skipped.append((key, ("unconfigured", f"يتطلب مفتاح {src['env_key']}")))
            continue
        applicable = [q for q in queries if q["indicator_type"] in conn.input_types]
        if not applicable:
            continue
        for q in applicable:
            runnable.append((conn, q))
    return runnable, skipped


def _run_connector(conn, query, search_id: int):
    started = datetime.utcnow()
    secret_key = conn.env_key
    ctx = {"secrets": {secret_key: get_source_secret(secret_key)} if secret_key else {}}
    run_cur = db.execute(
        "INSERT INTO source_runs(search_id,source_key,status) VALUES (?,?, 'running')",
        (search_id, conn.key),
    )
    run_id = run_cur.lastrowid
    db.execute("UPDATE sources SET request_count=request_count+1 WHERE key=?", (conn.key,))
    try:
        results = conn.run(query["indicator_type"], query["value"], ctx)
        count, review = _store_findings(search_id, run_id, conn, query, results)
        dur = int((datetime.utcnow() - started).total_seconds() * 1000)
        db.execute(
            """UPDATE source_runs SET status='ok', result_count=?, finished_at=?, duration_ms=?
               WHERE id=?""",
            (count, _now(), dur, run_id),
        )
        db.execute(
            "UPDATE sources SET last_success_at=?, last_error=NULL, status='ok' WHERE key=?",
            (_now(), conn.key),
        )
        return True, count, review
    except ConnectorError as e:
        dur = int((datetime.utcnow() - started).total_seconds() * 1000)
        status = "unconfigured" if getattr(e, "unconfigured", False) else "error"
        db.execute(
            """UPDATE source_runs SET status=?, error=?, finished_at=?, duration_ms=?
               WHERE id=?""",
            (status, str(e)[:500], _now(), dur, run_id),
        )
        db.execute("UPDATE sources SET last_error=? WHERE key=?", (str(e)[:500], conn.key))
        return False, 0, 0
    except Exception as e:  # noqa
        db.execute(
            "UPDATE source_runs SET status='error', error=?, finished_at=? WHERE id=?",
            (f"خطأ غير متوقع: {e}"[:500], _now(), run_id),
        )
        return False, 0, 0


def _store_findings(search_id, run_id, conn, query, results) -> tuple[int, int]:
    count = 0
    review = 0
    root_type = query["indicator_type"]
    root_id = er.upsert_entity(root_type, query.get("normalized_value") or query["value"],
                               display_name=query["value"])
    for res in results:
        d = res.to_dict()
        entity_id = er.upsert_entity(d["entity_type"], d["value"])
        is_demo = 0
        needs_review = d["confidence"] in ("weak", "unverified")
        if needs_review:
            review += 1
        db.execute(
            """INSERT INTO findings(search_id,source_run_id,entity_id,dataset_id,entity_type,
                 title,description,value,url,source_name,confidence,verification_status,
                 collected_at,raw_json,notes,is_demo)
               VALUES (?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (search_id, run_id, entity_id, d["entity_type"], d["title"], d["description"],
             d["value"][:1024], d["url"], conn.name, d["confidence"],
             d["verification_status"], d["collected_at"],
             json.dumps(d["raw"], ensure_ascii=False)[:20000], d["notes"], is_demo),
        )
        count += 1
        if entity_id and root_id and entity_id != root_id:
            rel = er.rel_type_for(root_type, d["entity_type"])
            er.link_relationship(
                root_id, entity_id, rel, source=conn.name, evidence_url=d["url"],
                confidence=d["confidence"],
                verification_status=d["verification_status"],
                reason=f"من نتيجة {conn.name}: {d['title']}", search_id=search_id,
            )
    return count, review


# --------------------------------------------------------------------------
# Internal dataset search
# --------------------------------------------------------------------------
def search_datasets(queries) -> list[dict]:
    out = []
    for q in queries:
        norm = q["normalized_value"]
        rows = db.query(
            """SELECT r.id, r.dataset_id, r.indicator_type, r.indicator_value,
                      r.normalized_value, r.record_json, r.created_at,
                      d.name AS dataset_name, d.source_name
               FROM dataset_records r JOIN datasets d ON d.id=r.dataset_id
               WHERE r.normalized_value=? OR r.record_json LIKE ?
               LIMIT 200""",
            (norm, f"%{q['value']}%"),
        )
        for r in rows:
            out.append(dict(r))
    return out


def _store_dataset_findings(search_id, internal) -> int:
    count = 0
    for rec in internal:
        entity_id = er.upsert_entity(rec["indicator_type"] or "keyword",
                                     rec["indicator_value"] or rec["normalized_value"])
        db.execute(
            """INSERT INTO findings(search_id,dataset_id,entity_id,entity_type,title,
                 description,value,url,source_name,confidence,verification_status,
                 collected_at,raw_json,notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (search_id, rec["dataset_id"], entity_id, rec["indicator_type"] or "keyword",
             f"سجل في مجموعة: {rec['dataset_name']}", rec["record_json"][:1000],
             rec["indicator_value"] or rec["normalized_value"], None, rec["dataset_name"],
             "direct", "verified", rec["created_at"],
             rec["record_json"][:20000], "مطابقة داخل قاعدة البيانات الاستخباراتية"),
        )
        count += 1
    return count


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------
def cancel_search(search_id: int) -> None:
    with _lock:
        _cancel.add(search_id)


def get_search(search_id: int) -> dict | None:
    s = db.query_one("SELECT * FROM searches WHERE id=?", (search_id,))
    if not s:
        return None
    queries = [dict(q) for q in db.query(
        "SELECT * FROM search_queries WHERE search_id=?", (search_id,))]
    runs = [dict(r) for r in db.query(
        """SELECT sr.*, s.name AS source_name FROM source_runs sr
           LEFT JOIN sources s ON s.key=sr.source_key
           WHERE sr.search_id=? ORDER BY sr.id""", (search_id,))]
    findings = [dict(f) for f in db.query(
        "SELECT * FROM findings WHERE search_id=? ORDER BY confidence, id", (search_id,))]
    grouped: dict[tuple, dict] = {}
    for f in findings:
        key = (f["entity_type"], (f["value"] or "").lower())
        g = grouped.setdefault(key, {
            "entity_type": f["entity_type"], "value": f["value"],
            "confidence": f["confidence"], "sources": [],
            "reference_count": 0, "verification_status": f["verification_status"],
        })
        g["reference_count"] += 1
        g["sources"].append({
            "source_name": f["source_name"], "title": f["title"],
            "url": f["url"], "confidence": f["confidence"],
            "collected_at": f["collected_at"], "description": f["description"],
            "dataset_id": f["dataset_id"], "entity_id": f["entity_id"],
        })
        if er.CONFIDENCE_ORDER.get(f["confidence"], 9) < er.CONFIDENCE_ORDER.get(g["confidence"], 9):
            g["confidence"] = f["confidence"]
    return {
        "search": dict(s),
        "queries": queries,
        "source_runs": runs,
        "findings": findings,
        "groups": list(grouped.values()),
        "graph": er.graph_for_search(search_id),
    }
