"""SQLite database access layer, migrations, and seed data."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from . import config

_local = threading.local()
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def connect() -> sqlite3.Connection:
    """One connection per thread; row access by name."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(config.DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        _local.conn = conn
    return conn


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return connect().execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    return connect().execute(sql, params).fetchone()


def execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    conn = connect()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur


def executemany(sql: str, seq) -> None:
    conn = connect()
    conn.executemany(sql, seq)
    conn.commit()


def transaction():
    return connect()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


def migrate() -> None:
    conn = connect()
    conn.executescript(SCHEMA_PATH.read_text("utf-8"))
    conn.commit()
    _seed()


# --------------------------------------------------------------------------
# Seed data
# --------------------------------------------------------------------------

PERMISSIONS = [
    ("search.run", "تشغيل عمليات البحث"),
    ("search.read", "قراءة عمليات البحث والنتائج"),
    ("search.delete", "حذف عمليات البحث"),
    ("datasets.read", "قراءة مجموعات البيانات"),
    ("datasets.write", "استيراد وتعديل مجموعات البيانات"),
    ("datasets.delete", "حذف مجموعات البيانات"),
    ("sources.manage", "إدارة المصادر والموصلات"),
    ("tools.run", "تشغيل أدوات الأمن السيبراني"),
    ("tools.manage", "إدارة مكتبة الأدوات"),
    ("reports.create", "إنشاء التقارير وتصديرها"),
    ("users.manage", "إدارة المستخدمين والصلاحيات"),
    ("audit.read", "قراءة سجل التدقيق"),
]

ROLE_PERMISSIONS = {
    "admin": [p[0] for p in PERMISSIONS],
    "analyst": [
        "search.run", "search.read", "search.delete",
        "datasets.read", "datasets.write",
        "tools.run", "reports.create",
    ],
    "viewer": ["search.read", "datasets.read", "reports.create"],
}

DEFAULT_SOURCES = [
    {
        "key": "dns_doh",
        "name": "DNS (Cloudflare DoH)",
        "category": "web",
        "description": "استعلام سجلات DNS العامة (A, AAAA, MX, NS, TXT) عبر DNS-over-HTTPS.",
        "official_url": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
        "input_types": ["domain", "email"],
        "requires_key": 0,
        "rate_limit": "لا يوجد حد معلن للاستخدام المعقول",
    },
    {
        "key": "crt_sh",
        "name": "crt.sh (شهادات رقمية)",
        "category": "domain",
        "description": "سجلات الشفافية للشهادات الرقمية لاستكشاف النطاقات الفرعية.",
        "official_url": "https://crt.sh/",
        "input_types": ["domain"],
        "requires_key": 0,
        "rate_limit": "استخدام معقول",
    },
    {
        "key": "rdap",
        "name": "RDAP (تسجيل النطاقات)",
        "category": "domain",
        "description": "بيانات تسجيل النطاق المتاحة علنًا عبر بروتوكول RDAP.",
        "official_url": "https://rdap.org/",
        "input_types": ["domain", "ip"],
        "requires_key": 0,
        "rate_limit": "حسب سجل النطاق",
    },
    {
        "key": "wayback",
        "name": "Wayback Machine (أرشيف عام)",
        "category": "web",
        "description": "لقطات الأرشيف العام للصفحات عبر CDX API.",
        "official_url": "https://web.archive.org/",
        "input_types": ["url", "domain"],
        "requires_key": 0,
        "rate_limit": "استخدام معقول",
    },
    {
        "key": "github",
        "name": "GitHub (حسابات ومستودعات عامة)",
        "category": "code",
        "description": "بحث عن أسماء المستخدمين والمستودعات العامة عبر GitHub REST API.",
        "official_url": "https://docs.github.com/rest",
        "input_types": ["username", "domain", "email"],
        "requires_key": 0,
        "env_key": "GITHUB_TOKEN",
        "rate_limit": "60/ساعة بدون مفتاح، 5000/ساعة بمفتاح",
    },
    {
        "key": "ip_info",
        "name": "ip-api.com (بيانات IP تقريبية)",
        "category": "ip",
        "description": "ASN ومزود الخدمة والموقع الجغرافي التقريبي لعناوين IP العامة.",
        "official_url": "https://ip-api.com/docs",
        "input_types": ["ip"],
        "requires_key": 0,
        "rate_limit": "45/دقيقة",
    },
    {
        "key": "gravatar",
        "name": "Gravatar (تحقق بصمة بريد)",
        "category": "email",
        "description": "فحص وجود صورة رمزية مرتبطة ببصمة البريد الإلكتروني.",
        "official_url": "https://gravatar.com/",
        "input_types": ["email"],
        "requires_key": 0,
        "rate_limit": "استخدام معقول",
    },
    {
        "key": "http_headers",
        "name": "HTTP Headers (رؤوس عامة)",
        "category": "web",
        "description": "قراءة رؤوس HTTP العامة لموقع على نطاق عام.",
        "official_url": "https://developer.mozilla.org/docs/Web/HTTP/Headers",
        "input_types": ["domain", "url"],
        "requires_key": 0,
        "rate_limit": "هدف عام واحد لكل طلب",
    },
]

DEFAULT_TOOLS = [
    ("nmap", "Nmap", "Network Discovery & Analysis", "اكتشاف الأجهزة والخدمات ضمن نطاقات مصرّح بها.", "https://nmap.org", "nmap"),
    ("tshark", "Wireshark / TShark", "Network Discovery & Analysis", "تحليل ملفات التقاط الشبكة PCAP.", "https://www.wireshark.org", "tshark"),
    ("tcpdump", "tcpdump", "Network Discovery & Analysis", "تحليل التقاطات الشبكة في البيئات المدعومة.", "https://www.tcpdump.org", "tcpdump"),
    ("theharvester", "theHarvester", "OSINT & Digital Footprinting", "جمع معلومات عامة عن النطاقات.", "https://github.com/laramies/theHarvester", "theHarvester"),
    ("sherlock", "Sherlock", "OSINT & Digital Footprinting", "البحث عن أسماء المستخدمين عبر الخدمات المدعومة.", "https://github.com/sherlock-project/sherlock", "sherlock"),
    ("exiftool", "ExifTool", "OSINT & Digital Footprinting", "قراءة البيانات الوصفية للملفات والصور.", "https://exiftool.org", "exiftool"),
    ("subfinder", "Subfinder", "OSINT & Digital Footprinting", "اكتشاف النطاقات الفرعية.", "https://github.com/projectdiscovery/subfinder", "subfinder"),
    ("amasoob", "Amass", "OSINT & Digital Footprinting", "رسم خريطة البنية الرقمية واكتشاف النطاقات الفرعية.", "https://github.com/owasp-amass/amass", "amass"),
    ("john", "John the Ripper", "Password Security & Digital Forensics", "تدقيق قوة كلمات المرور في حالات مصرّح بها.", "https://www.openwall.com/john/", "john"),
    ("hashcat", "Hashcat", "Password Security & Digital Forensics", "تدقيق كلمات المرور باستخدام تجزئات مصرّح بفحصها.", "https://hashcat.net/hashcat/", "hashcat"),
    ("yara", "YARA", "Password Security & Digital Forensics", "مطابقة الملفات مع قواعد كشف موثقة.", "https://virustotal.github.io/yara/", "yara"),
    ("volatility", "Volatility 3", "Password Security & Digital Forensics", "تحليل صور الذاكرة.", "https://github.com/volatilityfoundation/volatility3", "vol"),
    ("zap", "OWASP ZAP", "Web Security & Application Testing", "اختبار أمان تطبيقات الويب ضمن نطاق مصرّح به.", "https://www.zaproxy.org", "zap.sh"),
    ("nuclei", "Nuclei", "Web Security & Application Testing", "التحقق من مؤشرات الثغرات بقوالب موثوقة.", "https://github.com/projectdiscovery/nuclei", "nuclei"),
    ("testssl", "testssl.sh", "Web Security & Application Testing", "فحص إعدادات TLS لخوادم مصرّح بفحصها.", "https://testssl.sh", "testssl.sh"),
]


def _seed() -> None:
    conn = connect()
    # permissions
    for code, desc in PERMISSIONS:
        conn.execute(
            "INSERT OR IGNORE INTO permissions(code, description) VALUES (?,?)", (code, desc)
        )
    # roles
    roles = {
        "admin": "مدير المنصة بصلاحيات كاملة",
        "analyst": "محلل يستطيع تنفيذ البحث وإدارة البيانات",
        "viewer": "مستخدم قراءة فقط",
    }
    for name, desc in roles.items():
        conn.execute("INSERT OR IGNORE INTO roles(name, description) VALUES (?,?)", (name, desc))
    # role_permissions
    for role_name, perms in ROLE_PERMISSIONS.items():
        role_id = conn.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()[0]
        for p in perms:
            pid = conn.execute("SELECT id FROM permissions WHERE code=?", (p,)).fetchone()[0]
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES (?,?)",
                (role_id, pid),
            )
    # default sources
    for s in DEFAULT_SOURCES:
        conn.execute(
            """INSERT OR IGNORE INTO sources(key,name,category,description,official_url,
               input_types,requires_key,env_key,rate_limit,status)
               VALUES (?,?,?,?,?,?,?,?,?,'ok')""",
            (
                s["key"], s["name"], s["category"], s["description"], s["official_url"],
                json.dumps(s["input_types"]), s["requires_key"], s.get("env_key"), s.get("rate_limit"),
            ),
        )
    # default tools catalogue (installed status verified lazily)
    for slug, name, cat, desc, repo, binary in DEFAULT_TOOLS:
        conn.execute(
            """INSERT OR IGNORE INTO tools(slug,name,category,description,repo_url,requires,install_status)
               VALUES (?,?,?,?,?,?, 'not_installed')""",
            (slug, name, cat, desc, repo, binary),
        )
    conn.commit()
