"""Dashboard aggregation — all figures come from the live database."""
from __future__ import annotations

from . import database as db


def stats() -> dict:
    def one(sql, params=()):
        row = db.query_one(sql, params)
        return list(row)[0] if row else 0

    total_searches = one("SELECT COUNT(*) FROM searches")
    total_sources = one("SELECT COUNT(*) FROM sources")
    connected_sources = one("SELECT COUNT(*) FROM sources WHERE status='ok' AND enabled=1")
    total_records = one("SELECT COUNT(*) FROM dataset_records")
    total_datasets = one("SELECT COUNT(*) FROM datasets")
    total_reports = one("SELECT COUNT(*) FROM reports")
    needs_review = one("SELECT COUNT(*) FROM searches WHERE needs_review > 0")
    open_findings_review = one(
        "SELECT COUNT(*) FROM findings WHERE verification_status='unverified'")
    total_findings = one("SELECT COUNT(*) FROM findings")
    tool_tasks = one("SELECT COUNT(*) FROM tool_tasks")

    recent_searches = [dict(r) for r in db.query(
        """SELECT s.id, s.title, s.status, s.scope, s.result_count, s.created_at,
                  u.username FROM searches s LEFT JOIN users u ON u.id=s.user_id
           ORDER BY s.id DESC LIMIT 8""")]
    recent_imports = [dict(r) for r in db.query(
        """SELECT j.id, j.filename, j.status, j.imported_rows, j.duplicate_rows,
                  j.created_at, d.name AS dataset_name
           FROM dataset_import_jobs j LEFT JOIN datasets d ON d.id=j.dataset_id
           ORDER BY j.id DESC LIMIT 8""")]
    sources = [dict(r) for r in db.query(
        """SELECT key, name, category, enabled, status, last_success_at, request_count,
                  last_error, requires_key FROM sources ORDER BY category, name""")]

    activity = [dict(r) for r in db.query(
        """SELECT substr(created_at,1,10) AS day, COUNT(*) AS count
           FROM searches
           WHERE created_at >= datetime('now','-14 days')
           GROUP BY day ORDER BY day""")]

    findings_by_confidence = [dict(r) for r in db.query(
        """SELECT confidence, COUNT(*) AS count FROM findings
           GROUP BY confidence ORDER BY count DESC""")]

    return {
        "cards": {
            "total_searches": total_searches,
            "total_sources": total_sources,
            "connected_sources": connected_sources,
            "total_records": total_records,
            "total_datasets": total_datasets,
            "total_reports": total_reports,
            "needs_review": needs_review,
            "open_findings_review": open_findings_review,
            "total_findings": total_findings,
            "tool_tasks": tool_tasks,
        },
        "recent_searches": recent_searches,
        "recent_imports": recent_imports,
        "sources": sources,
        "activity": activity,
        "findings_by_confidence": findings_by_confidence,
    }
