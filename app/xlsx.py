"""Minimal XLSX reader using only the standard library (zipfile + XML).

Reads the first worksheet of an .xlsx workbook into a list of dict rows.
Supports shared strings and inline strings — enough for dataset import.
"""
from __future__ import annotations

import re
import zipfile
from xml.etree import ElementTree as ET

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
PKG_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"

_CELL_RE = re.compile(r"([A-Z]+)(\d+)")


def _col_to_index(col: str) -> int:
    idx = 0
    for ch in col:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def read_xlsx(path) -> list[dict]:
    with zipfile.ZipFile(path) as z:
        shared = _read_shared_strings(z)
        sheet_path = _first_sheet_path(z)
        if not sheet_path:
            return []
        root = ET.fromstring(z.read(sheet_path))
        rows = []
        for row in root.iter(f"{NS}row"):
            cells: dict[int, str] = {}
            for c in row.iter(f"{NS}c"):
                ref = c.get("r", "")
                m = _CELL_RE.match(ref)
                col = _col_to_index(m.group(1)) if m else len(cells)
                ctype = c.get("t")
                value = ""
                v = c.find(f"{NS}v")
                if ctype == "s" and v is not None:
                    value = shared[int(v.text)] if v.text and int(v.text) < len(shared) else ""
                elif ctype == "inlineStr":
                    is_el = c.find(f"{NS}is")
                    if is_el is not None:
                        value = "".join(t.text or "" for t in is_el.iter(f"{NS}t"))
                elif v is not None:
                    value = v.text or ""
                cells[col] = value
            if not cells:
                continue
            width = max(cells) + 1
            rows.append([cells.get(i, "") for i in range(width)])
    if not rows:
        return []
    header = [str(h).strip() or f"col{i+1}" for i, h in enumerate(rows[0])]
    out = []
    for r in rows[1:]:
        d = {header[i]: (r[i] if i < len(r) else "") for i in range(len(header))}
        out.append(d)
    return out


def _read_shared_strings(z: zipfile.ZipFile) -> list[str]:
    try:
        data = z.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(data)
    strings = []
    for si in root.iter(f"{NS}si"):
        strings.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
    return strings


def _first_sheet_path(z: zipfile.ZipFile) -> str | None:
    try:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    except KeyError:
        return None
    rid = None
    for sheet in wb.iter(f"{NS}sheet"):
        rid = sheet.get(f"{REL_NS}id")
        break
    if not rid:
        return None
    for rel in rels.iter(f"{PKG_REL_NS}Relationship"):
        if rel.get("Id") == rid:
            target = rel.get("Target", "")
            return "xl/" + target.lstrip("/").replace("xl/", "")
    return None
