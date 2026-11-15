"""Vendor-unique page definitions loaded from JSON files.

See definitions/README.md for the file format.
"""
import json
import os
import re

from .fields import Field, parse_int

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "definitions")


def _key(s):
    """'0x30' -> (0x30, 0), '0x30/0x01' -> (0x30, 1)."""
    parts = str(s).split("/")
    return parse_int(parts[0]), parse_int(parts[1]) if len(parts) > 1 else 0


def _fields(lst, where):
    try:
        return [Field.from_json(d) for d in lst or []]
    except (KeyError, ValueError) as e:
        raise ValueError(f"{where}: bad field definition ({e})") from None


class VendorDefs:
    """Merged definitions that apply to one drive."""

    def __init__(self):
        self.logs, self.modes, self.vpds, self.sources = {}, {}, {}, []

    def add_file(self, path, doc):
        self.sources.append(path)
        for k, v in (doc.get("log_pages") or {}).items():
            where = f"{os.path.basename(path)} log page {k}"
            page = {"name": v.get("name", "Vendor specific"), "layout": v.get("layout", "params"),
                    "fields": _fields(v.get("fields"), where), "params": {}}
            for pk, pv in (v.get("params") or {}).items():
                p = dict(pv)
                p["fields"] = _fields(pv.get("fields"), f"{where} param {pk}")
                if pk in ("*", "default"):
                    page["default_param"] = p
                else:
                    page["params"][parse_int(pk)] = p
            self.logs[_key(k)] = page
        for k, v in (doc.get("mode_pages") or {}).items():
            self.modes[_key(k)] = {"name": v.get("name", "Vendor specific"),
                                   "fields": _fields(v.get("fields"), f"{path} mode page {k}")}
        for k, v in (doc.get("vpd_pages") or {}).items():
            self.vpds[parse_int(k)] = {"name": v.get("name", "Vendor specific"),
                                       "fields": _fields(v.get("fields"), f"{path} VPD page {k}")}

    def log_page(self, page, sub=0):
        return self.logs.get((page, sub))

    def mode_page(self, page, sub=0):
        return self.modes.get((page, sub))

    def vpd_page(self, page):
        return self.vpds.get(page)


def _matches(doc, vendor, product, revision):
    m = doc.get("match") or {}
    for key, val in (("vendor", vendor), ("product", product), ("revision", revision)):
        pat = m.get(key)
        if pat and not re.search(pat, val or "", re.I):
            return False
    return True


def load(vendor="", product="", revision="", extra_dirs=(), force_files=()):
    """Load every definition file whose 'match' block fits this drive."""
    defs = VendorDefs()
    dirs = [BUILTIN_DIR] + [d for d in extra_dirs if d]
    env = os.environ.get("SASTOOL_DEFS")
    if env:
        dirs += env.split(os.pathsep)
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith(".json") or fn.startswith("_"):
                continue
            path = os.path.join(d, fn)
            with open(path, encoding="utf-8") as fh:
                try:
                    doc = json.load(fh)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{path}: invalid JSON ({e})") from None
            if _matches(doc, vendor, product, revision):
                defs.add_file(path, doc)
    for path in force_files:
        with open(path, encoding="utf-8") as fh:
            defs.add_file(path, json.load(fh))
    return defs
