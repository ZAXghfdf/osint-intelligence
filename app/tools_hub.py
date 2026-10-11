"""Cybersecurity Tools Hub — detection, allowlisted execution, unified adapters."""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
from datetime import datetime

from . import auth
from . import database as db
from . import security
from .config import (TOOL_MAX_CONCURRENT, TOOL_MAX_TIMEOUT, load_authorized_targets)

_sem = threading.Semaphore(TOOL_MAX_CONCURRENT)

# Per-tool execution templates. Flags are validated; never take raw shell input.
TOOL_TEMPLATES = {
    "nmap": {
        "task_types": ["service_scan"],
        "build": lambda t, o: ["nmap", "-sV", "--top-ports", str(_int(o.get("ports", "100"), 100)), "-oX", "-", t],
        "target_kinds": ["domain", "ip"],
        "adapter": "nmap_xml",
    },
    "tshark": {
        "task_types": ["analyze_pcap"],
        "build": lambda t, o: ["tshark", "-r", t, "-T", "json"],
        "target_kinds": ["file"],
        "adapter": "tshark_json",
    },
    "nuclei": {
        "task_types": ["template_scan"],
        "build": lambda t, o: ["nuclei", "-u", t, "-jsonl", "-silent"],
        "target_kinds": ["url", "domain"],
        "adapter": "nuclei_jsonl",
    },
    "exiftool": {
        "task_types": ["metadata"],
        "build": lambda t, o: ["exiftool", "-json", t],
        "target_kinds": ["file"],
        "adapter": "exiftool_json",
    },
    "testssl": {
        "task_types": ["tls_scan"],
        "build": lambda t, o: ["testssl.sh", "--jsonfile", "-", t],
        "target_kinds": ["domain"],
        "adapter": "generic",
    },
}

# Fallback: tools without an execution template are analysis/import-only.
GENERIC_TOOLS = {"theharvester", "sherlock", "subfinder", "amasoob", "john", "hashcat",
                 "yara", "volatility", "zap", "tcpdump"}


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def refresh_installation_status() -> list[dict]:
    out = []
    for t in db.query("SELECT * FROM tools"):
        binary = (t["requires"] or "").strip()
        if not binary:
            status, installed = "incompatible", 0
        elif shutil.which(binary):
            status, installed = "installed", 1
        else:
            status, installed = "not_installed", 0
        # Tools with no execution template on this host can still be imported/analyzed.
        if not installed and (t["slug"] in GENERIC_TOOLS):
            status = "needs_setup"
        db.execute(
            "UPDATE tools SET installed=?, install_status=?, last_checked_at=? WHERE id=?",
            (installed, status, _now(), t["id"]),
        )
        out.append({"slug": t["slug"], "status": status, "installed": installed})
    return out


def list_tools() -> list[dict]:
    return [dict(r) for r in db.query("SELECT * FROM tools ORDER BY category, name")]


def get_tool(slug: str) -> dict | None:
    row = db.query_one("SELECT * FROM tools WHERE slug=?", (slug,))
    return dict(row) if row else None


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------
def validate_target(tool_slug: str, target: str) -> tuple[bool, str]:
    tmpl = TOOL_TEMPLATES.get(tool_slug)
    if not tmpl:
        return False, "هذه الأداة غير مخصصة للتنفيذ المباشر في هذه البيئة (تحليل/استيراد فقط)"
    itype = security.detect_indicator_type(target)
    if tmpl["target_kinds"] != ["file"]:
        if itype not in tmpl["target_kinds"]:
            return False, f"نوع الهدف غير مدعوم لهذه الأداة ({itype})"
        ok, msg = security.safe_url(target if target.startswith("http") else f"http://{target}")
        if not ok:
            return False, f"الهدف محظور: {msg}"
    allowed = load_authorized_targets()
    if not allowed:
        return False, "لا توجد أهداف مصرّح بها. أضف الهدف إلى قائمة الأهداف المصرّح بها أولاً."
    norm_target = target.strip().lower().rstrip("/")
    norm_allowed = {a.strip().lower().rstrip("/") for a in allowed}
    if norm_target not in norm_allowed and not any(
        norm_target.endswith("." + a) or norm_target == a for a in norm_allowed
    ):
        return False, "الهدف غير مدرج في قائمة الأهداف المصرّح بفحصها"
    return True, ""


def run_task(user_ctx: dict, tool_slug: str, target: str, options: dict,
             search_id=None, timeout: int | None = None) -> dict:
    if "tools.run" not in user_ctx.get("permissions", set()):
        raise PermissionError("لا تملك صلاحية تشغيل الأدوات")
    tool = get_tool(tool_slug)
    if not tool:
        raise ValueError("أداة غير معروفة")
    if not tool["enabled"]:
        raise ValueError("الأداة معطّلة")
    tmpl = TOOL_TEMPLATES.get(tool_slug)
    if not tmpl:
        raise ValueError("هذه الأداة لا تدعم التنفيذ المباشر في هذه البيئة")
    ok, msg = validate_target(tool_slug, target)
    if not ok:
        # Persist a rejected task for auditability.
        db.execute(
            """INSERT INTO tool_tasks(tool_id,user_id,search_id,target,options_json,status,
                 finished_at,stderr) VALUES (?,?,?,?,?,'rejected',?,?)""",
            (tool["id"], user_ctx["id"], search_id, target,
             json.dumps(options, ensure_ascii=False), _now(), msg),
        )
        auth.audit(user_ctx["id"], "tool.run_rejected", "tool", tool_slug,
                   {"target": target, "reason": msg})
        raise ValueError(msg)

    to = min(int(timeout or TOOL_MAX_TIMEOUT), TOOL_MAX_TIMEOUT)
    try:
        cmd = tmpl["build"](target, options or {})
    except Exception as e:
        raise ValueError(f"خيارات غير صالحة: {e}")

    cur = db.execute(
        """INSERT INTO tool_tasks(tool_id,user_id,search_id,task_type,target,options_json,
             command,status,started_at,timeout_s) VALUES (?,?,?,?,?,?,?, 'running',?,?)""",
        (tool["id"], user_ctx["id"], search_id, tmpl["task_types"][0], target,
         json.dumps(options, ensure_ascii=False), " ".join(cmd), _now(), to),
    )
    task_id = cur.lastrowid
    auth.audit(user_ctx["id"], "tool.run", "tool_task", task_id,
               {"tool": tool_slug, "target": target, "options": options})

    result = _execute(task_id, cmd, to, tool, tmpl["adapter"], search_id)
    return result


def _execute(task_id, cmd, timeout, tool, adapter, search_id):
    with _sem:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=timeout, text=True, errors="replace"
            )
            stdout = proc.stdout[:500_000]
            stderr = proc.stderr[:50_000]
            status = "success" if proc.returncode == 0 else "failed"
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            stdout = (e.stdout or "")[:500_000] if isinstance(e.stdout, str) else ""
            stderr = "انتهت المهلة الزمنية"
            status, exit_code = "failed", -1
        except FileNotFoundError:
            stdout, stderr = "", "الأداة غير مثبتة على هذا النظام"
            status, exit_code = "failed", -2
        except Exception as e:  # noqa
            stdout, stderr = "", f"خطأ في التنفيذ: {e}"
            status, exit_code = "failed", -3

    results = normalize_output(tool, adapter, stdout, task_id, search_id)
    db.execute(
        """UPDATE tool_tasks SET status=?, finished_at=?, exit_code=?, stdout=?, stderr=?
           WHERE id=?""",
        (status, _now(), exit_code, stdout, stderr, task_id),
    )
    return {"task_id": task_id, "status": status, "exit_code": exit_code,
            "results": results, "stdout": stdout[:5000], "stderr": stderr}


def normalize_output(tool, adapter, stdout, task_id, search_id):
    """Adapters convert raw tool output into the unified result model."""
    parsed = []
    try:
        if adapter == "nmap_xml":
            parsed = _adapt_nmap(stdout, tool["name"])
        elif adapter == "tshark_json":
            parsed = _adapt_tshark(stdout, tool["name"])
        elif adapter == "nuclei_jsonl":
            parsed = _adapt_jsonl(stdout, tool["name"])
        elif adapter == "exiftool_json":
            parsed = _adapt_exiftool(stdout, tool["name"])
        else:
            parsed = [{
                "result_type": "raw", "title": "مخرجات أداة",
                "description": stdout[:500], "severity": None,
                "source_reference": None, "parsed_data": {"raw": stdout[:20000]},
            }]
    except Exception as e:  # noqa
        parsed = [{"result_type": "error", "title": "تعذّر تحليل المخرجات",
                   "description": str(e), "parsed_data": {}}]

    for item in parsed:
        db.execute(
            """INSERT INTO tool_results(task_id,tool_id,result_type,title,description,
                 severity,source_tool,source_reference,raw_output_ref,parsed_json,
                 verification_status)
               VALUES (?,?,?,?,?,?,?,?,?,?, 'unverified')""",
            (task_id, tool["id"], item.get("result_type"), item.get("title"),
             item.get("description"), item.get("severity"), tool["name"],
             item.get("source_reference"), None,
             json.dumps(item.get("parsed_data", {}), ensure_ascii=False)[:20000]),
        )
    return parsed


def _adapt_nmap(stdout, tool_name):
    import xml.etree.ElementTree as ET
    results = []
    root = ET.fromstring(stdout)
    for host in root.iter("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        for port in host.iter("port"):
            state = port.find("state")
            service = port.find("service")
            if state is not None and state.get("state") == "open":
                svc = f"{service.get('name')} {service.get('product','')}" if service is not None else ""
                results.append({
                    "result_type": "open_port",
                    "title": f"منفذ مفتوح {port.get('portid')}/{port.get('protocol')}",
                    "description": f"{addr} — {svc.strip()}",
                    "source_reference": f"{addr}:{port.get('portid')}",
                    "parsed_data": {"host": addr, "port": port.get("portid"),
                                    "protocol": port.get("protocol"), "service": svc.strip()},
                })
    return results


def _adapt_tshark(stdout, tool_name):
    data = json.loads(stdout or "[]")
    packets = data if isinstance(data, list) else [data]
    proto_counts: dict[str, int] = {}
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {}) if isinstance(pkt, dict) else {}
        proto = layers.get("frame", {}).get("frame.protocols", "unknown")
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    return [{"result_type": "pcap_summary", "title": "ملخص تحليل PCAP",
             "description": f"عدد الحزم: {len(packets)}",
             "parsed_data": {"packet_count": len(packets), "protocols": proto_counts}}]


def _adapt_jsonl(stdout, tool_name):
    results = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append({
            "result_type": obj.get("type", "finding"),
            "title": obj.get("info", {}).get("name", "نتيجة"),
            "description": obj.get("matched-at", ""),
            "severity": obj.get("info", {}).get("severity"),
            "source_reference": obj.get("matched-at"),
            "parsed_data": obj,
        })
    return results


def _adapt_exiftool(stdout, tool_name):
    data = json.loads(stdout or "[]")
    results = []
    for obj in data if isinstance(data, list) else [data]:
        results.append({
            "result_type": "metadata",
            "title": "بيانات وصفية للملف",
            "description": f"SourceFile: {obj.get('SourceFile')}",
            "parsed_data": obj,
        })
    return results


def list_tasks(limit: int = 100) -> list[dict]:
    return [dict(r) for r in db.query(
        """SELECT tt.*, t.name AS tool_name, u.username FROM tool_tasks tt
           LEFT JOIN tools t ON t.id=tt.tool_id
           LEFT JOIN users u ON u.id=tt.user_id
           ORDER BY tt.id DESC LIMIT ?""", (limit,))]


def task_details(task_id: int) -> dict | None:
    row = db.query_one("SELECT * FROM tool_tasks WHERE id=?", (task_id,))
    if not row:
        return None
    results = [dict(r) for r in db.query("SELECT * FROM tool_results WHERE task_id=?", (task_id,))]
    d = dict(row)
    d["results"] = results
    return d


# --------------------------------------------------------------------------
# GitHub Tool Discovery
# --------------------------------------------------------------------------
def github_discover(query: str, category: str = "", per_page: int = 10) -> list[dict]:
    from .connectors.base import ConnectorError
    from .connectors.github import GithubConnector

    conn = GithubConnector()
    q = query if "topic:" in query or "language:" in query else query
    url = f"https://api.github.com/search/repositories?q={_quote(q)}&sort=stars&per_page={per_page}"
    try:
        data, _, _ = conn.http_get(url, headers={"Accept": "application/vnd.github+json"})
    except ConnectorError as e:
        raise ValueError(str(e))
    out = []
    for item in (data.get("items", []) if isinstance(data, dict) else []):
        out.append({
            "repo_full_name": item.get("full_name"),
            "name": item.get("name"),
            "description": item.get("description"),
            "url": item.get("html_url"),
            "language": item.get("language"),
            "license": (item.get("license") or {}).get("spdx_id"),
            "stars": item.get("stargazers_count"),
            "pushed_at": item.get("pushed_at"),
            "archived": 1 if item.get("archived") else 0,
            "category": category,
        })
    return out


def _quote(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s)


def save_github_project(data: dict, user_id: int) -> int:
    existing = db.query_one("SELECT id FROM github_projects WHERE repo_full_name=?",
                            (data["repo_full_name"],))
    if existing:
        return existing["id"]
    cur = db.execute(
        """INSERT INTO github_projects(repo_full_name,name,description,url,language,license,
             stars,pushed_at,category,archived,status,added_by)
           VALUES (?,?,?,?,?,?,?,?,?,?, 'pending_review', ?)""",
        (data["repo_full_name"], data.get("name"), data.get("description"), data.get("url"),
         data.get("language"), data.get("license"), data.get("stars", 0),
         data.get("pushed_at"), data.get("category"), data.get("archived", 0), user_id),
    )
    return cur.lastrowid


def list_github_projects() -> list[dict]:
    return [dict(r) for r in db.query("SELECT * FROM github_projects ORDER BY id DESC")]


def review_github_project(project_id: int, decision: str, reason: str, user_ctx: dict) -> None:
    status = {"accept": "accepted", "reject": "rejected", "incompatible": "incompatible"}.get(
        decision, "pending_review"
    )
    db.execute(
        """UPDATE github_projects SET status=?, review_decision=?, review_reason=?,
           updated_at=? WHERE id=?""",
        (status, decision, reason, _now(), project_id),
    )
    auth.audit(user_ctx["id"], "github.review", "github_project", project_id,
               {"decision": decision, "reason": reason})
