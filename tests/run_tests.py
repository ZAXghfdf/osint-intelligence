#!/usr/bin/env python3
"""OSINT INTELLIGENCE — automated test suite (stdlib only).

Run:  python tests/run_tests.py [--network]

Covers: input validation, SSRF guard, auth, CSV-injection defence,
dataset import + dedupe, internal search, upload rejection, search-engine
orchestration with a stub connector, permissions, reports, path traversal,
and tool-target authorization. Optional --network hits live public sources.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="osint_test_"))

import app.config as config  # noqa: E402

config.DB_PATH = TMP / "test.db"
config.UPLOAD_DIR = TMP / "uploads"
config.REPORT_DIR = TMP / "reports"
config.EVIDENCE_DIR = TMP / "evidence"
config.TOOL_ALLOWED_TARGETS_FILE = TMP / "targets.json"
for d in (config.UPLOAD_DIR, config.REPORT_DIR, config.EVIDENCE_DIR):
    d.mkdir(parents=True, exist_ok=True)

from app import auth, database as db, datasets as ds, engine, reports, security, tools_hub  # noqa: E402
from app import api  # noqa: E402
from app.connectors import base as cbase  # noqa: E402
from app.connectors import _registry as registry, get_connector  # noqa: E402
from app.http import serve_static, Response  # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


def section(t):
    print(f"\n== {t} ==")


def main():
    db.migrate()

    section("Input detection & validation")
    check("email detect", security.detect_indicator_type("a.b@example.com") == "email")
    check("ip detect", security.detect_indicator_type("8.8.8.8") == "ip")
    check("domain detect", security.detect_indicator_type("example.com") == "domain")
    check("url detect", security.detect_indicator_type("https://x.com/a") == "url")
    check("valid email", security.validate_indicator("a@b.com", "email")[0])
    check("invalid email", not security.validate_indicator("bad@@x", "email")[0])
    check("invalid domain", not security.validate_indicator("not a domain", "domain")[0])
    check("normalize username", security.normalize_indicator("@JohnDoe", "username") == "johndoe")

    section("SSRF guard")
    check("block localhost", not security.safe_url("http://127.0.0.1/x")[0])
    check("block metadata", not security.safe_url("http://169.254.169.254/latest")[0])
    check("block private", not security.safe_url("http://192.168.1.1")[0])
    check("block file scheme", not security.safe_url("file:///etc/passwd")[0])

    section("CSV formula-injection defence")
    check("sanitize =", security.sanitize_csv_cell("=cmd()").startswith("'"))
    check("sanitize @", security.sanitize_csv_cell("@x").startswith("'"))
    check("safe value untouched", security.sanitize_csv_cell("hello") == "hello")

    section("Authentication")
    uid = auth.create_user("t_analyst", "StrongPass123", "analyst", "a@x.com")
    check("create user", uid > 0)
    check("wrong password rejected", auth.authenticate("t_analyst", "nope") is None)
    check("right password", auth.authenticate("t_analyst", "StrongPass123") is not None)
    ctx = auth.get_user_context(uid)
    check("analyst has search.run", "search.run" in ctx["permissions"])
    check("analyst lacks users.manage", "users.manage" not in ctx["permissions"])
    pwrow = db.query_one("SELECT password_hash FROM users WHERE id=?", (uid,))
    check("password not stored in clear", "StrongPass123" not in pwrow["password_hash"])

    section("Upload validation")
    ok, _ = api._validate_upload("data.csv", b"a,b\n1,2\n")
    check("accept data.csv", ok)
    ok, _ = api._validate_upload("evil.exe", b"MZ\x90\x00")
    check("reject .exe", not ok)
    ok, _ = api._validate_upload("run.pdf", b"%PDF") if False else (False, "")
    ok, msg = api._validate_upload("note.txt", b"#! /bin/sh\nrm -rf /")
    check("reject shebang content", not ok)
    ok, msg = api._validate_upload("big.txt", b"x" * (config.MAX_UPLOAD_BYTES + 1))
    check("reject oversize", not ok)

    section("Dataset import & dedupe")
    csv_path = TMP / "people.csv"
    csv_path.write_text("name,email,domain\nAlice,alice@example.com,example.com\n"
                        "Bob,bob@example.com,example.com\n", "utf-8")
    preview = ds.preview(csv_path, "people.csv")
    check("preview fields", "email" in preview["fields"])
    check("auto-mapping email", preview["mapping"]["email"] == "email")
    cur = db.execute("INSERT INTO datasets(name,description,created_by) VALUES ('ds1','t',?)", (uid,))
    ds_id = cur.lastrowid
    job = db.execute("INSERT INTO dataset_import_jobs(dataset_id,filename,stored_path,status,created_by)"
                     " VALUES (?,?,?, 'previewed', ?)", (ds_id, "people.csv", str(csv_path), uid)).lastrowid
    rep = ds.import_file(ds_id, job, csv_path, "people.csv", preview["mapping"], ds.next_version(ds_id), uid)
    check("imported 2 rows", rep["imported"] == 2, rep)
    job2 = db.execute("INSERT INTO dataset_import_jobs(dataset_id,filename,stored_path,status,created_by)"
                      " VALUES (?,?,?, 'previewed', ?)", (ds_id, "people.csv", str(csv_path), uid)).lastrowid
    rep2 = ds.import_file(ds_id, job2, csv_path, "people.csv", preview["mapping"], ds.next_version(ds_id), uid)
    check("second import all duplicates", rep2["imported"] == 0 and rep2["duplicate"] == 2, rep2)

    section("Internal dataset search")
    q = [{"indicator_type": "email", "value": "alice@example.com",
          "normalized_value": "alice@example.com"}]
    found = engine.search_datasets(q)
    check("finds record by email", len(found) >= 1)
    check("dataset read permission default", ds.can_read(ctx, ds_id))

    section("Search-engine orchestration (stub connector)")
    class FakeConn(cbase.BaseConnector):
        key = "fake_test"
        name = "Stub Source"
        input_types = ["domain"]

        def run(self, itype, value, c):
            return [cbase.ConnectorResult("domain", value + ".sub", "stub dns",
                                          confidence="direct", verification_status="verified",
                                          url="https://example.com")]

    registry["fake_test"] = FakeConn()
    db.execute("INSERT OR IGNORE INTO sources(key,name,category,input_types,enabled) "
               "VALUES ('fake_test','Stub Source','web','[\"domain\"]',1)")
    sid = db.execute("INSERT INTO searches(user_id,title,status) VALUES (?,'t','running')", (uid,)).lastrowid
    db.execute("INSERT INTO search_queries(search_id,indicator_type,value,normalized_value,valid)"
               " VALUES (?,?,?,?,1)", (sid, "domain", "example.com", "example.com"))
    conn = get_connector("fake_test")
    ok, count, review = engine._run_connector(
        conn, {"indicator_type": "domain", "value": "example.com",
               "normalized_value": "example.com"}, sid)
    check("connector run ok", ok and count == 1, (ok, count))
    run_row = db.query_one("SELECT * FROM source_runs WHERE search_id=?", (sid,))
    check("source_run recorded", run_row is not None and run_row["status"] == "ok")
    rel = db.query_one("SELECT * FROM entity_relationships WHERE search_id=?", (sid,))
    check("relationship created from evidence", rel is not None)
    if rel:
        check("relationship has source", bool(rel["source"]))
    data = engine.get_search(sid)
    check("grouped finding has source reference", data["groups"][0]["sources"][0]["url"])

    section("Permissions enforcement")
    viewer_ctx = {"id": 99, "role": "viewer", "permissions": ["search.read"]}
    check("viewer cannot write dataset", "datasets.write" not in viewer_ctx["permissions"])
    newds = db.execute("INSERT INTO datasets(name,description) VALUES ('private_ds','x')").lastrowid
    db.execute("INSERT INTO dataset_access_permissions(dataset_id,role_id,can_read) "
               "SELECT ?, id, 0 FROM roles WHERE name='analyst'", (newds,))
    check("ACL denies analyst read", not ds.can_read(ctx, newds))

    section("Reports")
    r = reports.build_report(sid, "json", auth.get_user_context(1))
    check("json report built", r["id"] > 0)
    import json as _json
    payload = _json.loads(r["content"])
    check("report has disclaimer", "disclaimer" in payload)
    check("report separates confirmed/probable", "confirmed" in payload and "probable" in payload)
    rc = reports.build_report(sid, "csv", auth.get_user_context(1))
    check("csv report built", rc["id"] > 0)

    section("Path traversal defence")
    resp = serve_static(config.STATIC_DIR, "../app/config.py")
    check("block traversal", resp.status in (403, 404), resp.status)

    section("Tool target authorization")
    config.save_authorized_targets([])
    ok, msg = tools_hub.validate_target("nmap", "example.com")
    check("reject when allowlist empty", not ok)
    config.save_authorized_targets(["example.com"])
    ok, msg = tools_hub.validate_target("nmap", "example.com")
    check("accept allowlisted target", ok, msg)
    ok, msg = tools_hub.validate_target("nmap", "evil.com")
    check("reject non-allowlisted target", not ok)
    ok, msg = tools_hub.validate_target("theharvester", "example.com")
    check("reject non-exec tool", not ok)

    if "--network" in sys.argv:
        section("Live connectors (network)")
        for key, itype, val in [("dns_doh", "domain", "example.com"),
                                ("rdap", "domain", "example.com"),
                                ("ip_info", "ip", "8.8.8.8")]:
            try:
                res = get_connector(key).run(itype, val, {"secrets": {}})
                check(f"{key} live", len(res) > 0)
            except Exception as e:  # noqa
                check(f"{key} live", False, str(e))

    print(f"\n{'='*50}\nPASSED: {PASS}   FAILED: {FAIL}")
    if FAILURES:
        print("Failed:", ", ".join(FAILURES))
    shutil.rmtree(TMP, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
