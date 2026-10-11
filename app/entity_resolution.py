"""Entity Resolution Service.

Normalizes indicators, upserts entities, discovers direct/probable matches and
records relationships with a traceable evidence source. It never treats an
automated inference as a confirmed fact.
"""
from __future__ import annotations

from datetime import datetime

from . import database as db
from . import security

# Relationship inference table: (input_type, finding_type) -> rel_type
RELTYPE_MAP = {
    ("domain", "domain"): "has_subdomain_or_dns",
    ("domain", "service"): "serves_http",
    ("domain", "url"): "references_url",
    ("domain", "organization"): "registered_by",
    ("domain", "email"): "linked_email",
    ("email", "domain"): "uses_domain",
    ("email", "username"): "may_belong_to",
    ("username", "username"): "same_handle",
    ("username", "url"): "has_profile",
    ("username", "domain"): "references_domain",
    ("ip", "organization"): "operated_by",
    ("ip", "domain"): "hosts_domain",
    ("url", "url"): "references_url",
    ("phone", "organization"): "operated_by",
    ("keyword", "url"): "matches_query",
    ("keyword", "domain"): "matches_query",
}

CONFIDENCE_ORDER = {"direct": 0, "probable": 1, "weak": 2, "unverified": 3}


def normalize(entity_type: str, value: str) -> str:
    return security.normalize_indicator(str(value), entity_type)


def upsert_entity(entity_type: str, value: str, display_name: str | None = None) -> int | None:
    value = (value or "").strip()
    if not value or len(value) > 1024:
        return None
    norm = normalize(entity_type, value)
    if not norm:
        return None
    row = db.query_one(
        "SELECT id FROM entities WHERE entity_type=? AND normalized_value=?",
        (entity_type, norm),
    )
    if row:
        return row["id"]
    cur = db.execute(
        "INSERT INTO entities(entity_type,value,normalized_value,display_name) VALUES (?,?,?,?)",
        (entity_type, value[:1024], norm, display_name),
    )
    return cur.lastrowid


def link_relationship(from_id, to_id, rel_type, *, source="", evidence_url="",
                      confidence="probable", verification_status="unverified",
                      reason="", search_id=None) -> None:
    if not from_id or not to_id or from_id == to_id:
        return
    existing = db.query_one(
        """SELECT id FROM entity_relationships
           WHERE from_entity_id=? AND to_entity_id=? AND rel_type=?""",
        (from_id, to_id, rel_type),
    )
    if existing:
        db.execute(
            "UPDATE entity_relationships SET last_seen_at=datetime('now') WHERE id=?",
            (existing["id"],),
        )
        return
    db.execute(
        """INSERT INTO entity_relationships
           (from_entity_id,to_entity_id,rel_type,source,evidence_url,confidence,
            verification_status,reason,search_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (from_id, to_id, rel_type, source, evidence_url, confidence,
         verification_status, reason, search_id),
    )


def rel_type_for(from_type: str, to_type: str) -> str:
    return RELTYPE_MAP.get((from_type, to_type), "related_to")


def graph_for_search(search_id: int) -> dict:
    """Build graph nodes/edges for a search from stored findings/relationships."""
    rows = db.query(
        """SELECT e.id, e.entity_type, e.value, e.normalized_value,
                  COUNT(f.id) AS finding_count
           FROM entities e JOIN findings f ON f.entity_id=e.id
           WHERE f.search_id=? GROUP BY e.id""",
        (search_id,),
    )
    nodes = [dict(r) for r in rows]
    ids = [n["id"] for n in nodes]
    edges = []
    if ids:
        placeholders = ",".join("?" * len(ids))
        edges = [
            dict(r)
            for r in db.query(
                f"""SELECT r.*, fe.value AS from_value, te.value AS to_value,
                           fe.entity_type AS from_type, te.entity_type AS to_type
                    FROM entity_relationships r
                    JOIN entities fe ON fe.id=r.from_entity_id
                    JOIN entities te ON te.id=r.to_entity_id
                    WHERE r.search_id=? OR r.from_entity_id IN ({placeholders})
                          OR r.to_entity_id IN ({placeholders})""",
                tuple([search_id] + ids + ids),
            )
        ]
    return {"nodes": nodes, "edges": edges}


def global_graph(limit: int = 400) -> dict:
    nodes = [
        dict(r)
        for r in db.query(
            "SELECT id, entity_type, value, normalized_value FROM entities LIMIT ?", (limit,)
        )
    ]
    edges = [
        dict(r)
        for r in db.query(
            """SELECT r.*, fe.value AS from_value, te.value AS to_value,
                      fe.entity_type AS from_type, te.entity_type AS to_type
               FROM entity_relationships r
               JOIN entities fe ON fe.id=r.from_entity_id
               JOIN entities te ON te.id=r.to_entity_id
               WHERE r.from_entity_id IN (SELECT id FROM entities LIMIT ?)
                 AND r.to_entity_id IN (SELECT id FROM entities LIMIT ?)
               LIMIT 2000""",
            (limit, limit),
        )
    ]
    return {"nodes": nodes, "edges": edges}


def node_details(entity_id: int) -> dict | None:
    ent = db.query_one("SELECT * FROM entities WHERE id=?", (entity_id,))
    if not ent:
        return None
    findings = db.query(
        """SELECT f.id, f.title, f.description, f.url, f.confidence,
                  f.verification_status, f.collected_at, f.source_name, f.search_id
           FROM findings f WHERE f.entity_id=? ORDER BY f.collected_at DESC LIMIT 100""",
        (entity_id,),
    )
    rels = db.query(
        """SELECT r.rel_type, r.source, r.evidence_url, r.confidence,
                  r.verification_status, r.reason,
                  e2.id AS other_id, e2.value AS other_value, e2.entity_type AS other_type
           FROM entity_relationships r
           JOIN entities e2 ON e2.id = CASE WHEN r.from_entity_id=? THEN r.to_entity_id
                                            ELSE r.from_entity_id END
           WHERE r.from_entity_id=? OR r.to_entity_id=?""",
        (entity_id, entity_id, entity_id),
    )
    return {
        "entity": dict(ent),
        "findings": [dict(f) for f in findings],
        "relationships": [dict(r) for r in rels],
    }
