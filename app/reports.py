"""Report generation and export (CSV / JSON / printable HTML 'PDF')."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from html import escape

from . import auth
from . import database as db
from . import engine
from . import security
from .config import REPORT_DIR


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _collect(search_id: int) -> dict:
    data = engine.get_search(search_id)
    return data


def build_report(search_id: int, fmt: str, user_ctx: dict, title: str = "") -> dict:
    data = _collect(search_id)
    if not data:
        raise ValueError("لم يتم العثور على عملية البحث")
    s = data["search"]
    findings = data["findings"]
    confirmed = [f for f in findings if f["confidence"] == "direct"]
    probable = [f for f in findings if f["confidence"] != "direct"]
    report_title = title or f"تقرير بحث #{search_id} — {s['title']}"
    meta = {
        "generated_at": _now(),
        "search_id": search_id,
        "scope": s["scope"],
        "sources": sorted({r["source_key"] for r in data["source_runs"]}),
        "confirmed_count": len(confirmed),
        "probable_count": len(probable),
    }
    fmt = fmt.lower()
    if fmt == "json":
        content = json.dumps({
            "meta": meta,
            "search": s,
            "queries": data["queries"],
            "source_runs": data["source_runs"],
            "confirmed": confirmed,
            "probable": probable,
            "graph": data["graph"],
            "disclaimer": DISCLAIMER,
        }, ensure_ascii=False, indent=2)
        ext, ctype = ".json", "application/json"
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "title", "url", "source", "confidence",
                    "verification", "collected_at"])
        for f in findings:
            w.writerow([
                security.sanitize_csv_cell(f["entity_type"]),
                security.sanitize_csv_cell(f["value"]),
                security.sanitize_csv_cell(f["title"]),
                security.sanitize_csv_cell(f["url"]),
                security.sanitize_csv_cell(f["source_name"]),
                security.sanitize_csv_cell(f["confidence"]),
                security.sanitize_csv_cell(f["verification_status"]),
                security.sanitize_csv_cell(f["collected_at"]),
            ])
        content = buf.getvalue()
        ext, ctype = ".csv", "text/csv"
    elif fmt in ("pdf", "html"):
        content = _html_report(report_title, meta, data, confirmed, probable)
        ext, ctype = ".html", "text/html"
    else:
        raise ValueError("صيغة غير مدعومة")

    filename = f"report_{search_id}_{int(datetime.utcnow().timestamp())}{ext}"
    path = REPORT_DIR / filename
    path.write_text(content, encoding="utf-8")
    cur = db.execute(
        """INSERT INTO reports(search_id,user_id,title,format,file_path,meta_json)
           VALUES (?,?,?,?,?,?)""",
        (search_id, user_ctx["id"], report_title, fmt, str(path),
         json.dumps(meta, ensure_ascii=False)),
    )
    auth.audit(user_ctx["id"], "report.create", "report", cur.lastrowid,
               {"search_id": search_id, "format": fmt})
    return {"id": cur.lastrowid, "filename": filename, "path": str(path),
            "content": content, "content_type": ctype, "meta": meta}


DISCLAIMER = ("تنبيه: البيانات المفتوحة قد تكون قديمة أو غير دقيقة. النتائج المحتملة "
              "لا تُعد حقائق مؤكدة، ويلزم التحقق البشري قبل أي استخدام.")


def _html_report(title, meta, data, confirmed, probable) -> str:
    def rows(items):
        if not items:
            return "<tr><td colspan='6'>لا توجد</td></tr>"
        out = []
        for f in items:
            url = f["url"] or ""
            link = f"<a href='{escape(url)}'>{escape(url)}</a>" if url else "-"
            out.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    escape(str(f["entity_type"])), escape(str(f["value"])),
                    escape(str(f["title"] or "")), link, escape(str(f["source_name"] or "")),
                    escape(str(f["confidence"])))
            )
        return "".join(out)

    sources = "".join(f"<li>{escape(r['source_key'])} — {escape(r['status'])}</li>"
                      for r in data["source_runs"])
    return f"""<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>{escape(title)}</title>
<style>body{{font-family:sans-serif;background:#14161a;color:#e8e8ea;padding:24px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th,td{{border:1px solid #333;padding:6px;text-align:right;font-size:13px}}
th{{background:#2a2e35}} a{{color:#e0554f}} h1,h2{{color:#fff}}</style></head><body>
<h1>OSINT INTELLIGENCE — {escape(title)}</h1>
<p><b>وقت الإعداد:</b> {escape(meta['generated_at'])} |
<b>معرّف البحث:</b> {meta['search_id']} | <b>النطاق:</b> {escape(str(meta['scope']))}</p>
<h2>المصادر المستخدمة</h2><ul>{sources}</ul>
<h2>النتائج المؤكدة ({len(confirmed)})</h2>
<table><tr><th>النوع</th><th>القيمة</th><th>الوصف</th><th>الرابط</th><th>المصدر</th><th>الثقة</th></tr>
{rows(confirmed)}</table>
<h2>النتائج المحتملة ({len(probable)})</h2>
<table><tr><th>النوع</th><th>القيمة</th><th>الوصف</th><th>الرابط</th><th>المصدر</th><th>الثقة</th></tr>
{rows(probable)}</table>
<p style="color:#c9a227">{escape(DISCLAIMER)}</p>
</body></html>"""


def list_reports(user_ctx: dict) -> list[dict]:
    if user_ctx.get("role") == "admin":
        rows = db.query("SELECT * FROM reports ORDER BY id DESC LIMIT 200")
    else:
        rows = db.query("SELECT * FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 200",
                        (user_ctx["id"],))
    return [dict(r) for r in rows]
