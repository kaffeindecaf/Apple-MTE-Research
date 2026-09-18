"""Shared helpers for the MTE contribution tools.

Used by mte_crash_scan.py, mte_device_report.py and mte_insn_census.py.
Stdlib only for everything that touches user data (parsing, redaction);
capstone is an optional dependency of the instruction census.
"""

import json
import os
import re

# ---------------------------------------------------------------- signatures

# MTE markers that show up in crash reports, panics, syslogs and binaries.
# (label, regex, class) where class groups the finding for reporting.
MTE_SIGNATURES = [
    ("EXC_ARM_MTE_TAGCHECK_FAIL", r"EXC_ARM_MTE_TAGCHECK_FAIL", "tag-check-fault"),
    ("EXC_ARM_MTE_CANONICAL_FAIL", r"EXC_ARM_MTE_CANONICAL_FAIL", "canonical-fault"),
    ("GUARD_EXC_MTE_SYNC_FAULT", r"GUARD_EXC_MTE_SYNC_FAULT", "guard-exception"),
    ("GUARD_EXC_MTE_ASYNC_USER_FAULT", r"GUARD_EXC_MTE_ASYNC_USER_FAULT", "guard-exception"),
    ("GUARD_EXC_MTE_ASYNC_KERN_FAULT", r"GUARD_EXC_MTE_ASYNC_KERN_FAULT", "guard-exception"),
    ("MTE_FAIL", r"MTE_FAIL", "termination"),
    ("MTE_FAIL code 262", r"code 262", "termination"),
    ("mteState enabled", r"[Mm]teState\s*:?\s*[\"']?enabled", "mte-state"),
    ("isMTECrash", r"isMTECrash", "reporting"),
    ("mtePageTags", r"mtePageTags", "reporting"),
    ("MTE Page Tags", r"MTE Page Tags", "reporting"),
    ("MTE Malloc Size Class", r"MTE Malloc Size Class", "reporting"),
    ("libsystem_sanitizers", r"libsystem_sanitizers", "reporting"),
    ("weak-table unregister", r"Attempted to unregister unknown __weak variable",
     "weak-table"),
    ("SEGV_MTESERR", r"SEGV_MTESERR", "android"),
]

MTE_EXCEPTION_CODES = {
    "0x106": "EXC_ARM_MTE_TAGCHECK_FAIL (tag check failure)",
    "0x107": "EXC_ARM_MTE_CANONICAL_FAIL (canonical tag access fail)",
    "0x105": "EXC_ARM_PAC_FAIL (context only, not MTE)",
}

# ------------------------------------------------------------------- devices

# ProductType prefixes -> (family, chip, MTE capable). Kept deliberately
# coarse: the repo's locked facts put the A19/T8150 generation at the
# iPhone18,* product family and M5 at t8142 (S5, S51). Anything not listed
# here is reported as unknown rather than guessed.
DEVICE_TABLE = [
    ("iPhone18,", "iPhone 17 family / 17e", "A19 (T8150)", True),
    ("iPhone17,", "iPhone 16 family", "A18", False),
    ("iPhone16,", "iPhone 15 family", "A16 / A17 Pro", False),
    ("iPhone15,", "iPhone 14 family", "A15 / A16", False),
    ("iPhone14,", "iPhone 13 / 14", "A15 / A16", False),
    ("iPhone13,", "iPhone 12 family", "A14", False),
    ("iPhone12,", "iPhone 11 / SE2", "A13", False),
    ("iPhone11,", "iPhone XR / XS", "A12", False),
    ("iPad13,", "iPad Pro (M1) / Air (M1)", "M1", False),
    ("iPad14,", "iPad Pro (M2)", "M2", False),
    ("iPad16,", "iPad Pro (M4)", "M4", False),
]

MAC_CHIPS_WITH_MTE = ("M5",)


def device_verdict(product_type):
    """Return (family, chip, mte_capable, note) for a ProductType string."""
    pt = (product_type or "").strip()
    if not pt:
        return ("unknown", "unknown", None, "no ProductType reported")
    for prefix, family, chip, capable in DEVICE_TABLE:
        if pt.startswith(prefix):
            note = ""
            if pt.startswith("iPhone18,") and pt >= "iPhone18,4":
                note = "tag storage present in its IPSW (S51)"
            return (family, chip, capable, note)
    if pt.startswith(("Mac", "iMac", "MacBook")):
        return (pt, "Apple Silicon", None,
                "Macs: only M5 (t8142) has MIE so far, check About This Mac "
                "or sysctl machdep.cpu.brand_string and report the value")
    return (pt, "unknown", None, "not in the table yet, please report it")


# ------------------------------------------------------------------ redaction

_REDACT_RULES = [
    ("udid", re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b"), "<UDID>"),
    ("legacy-udid", re.compile(r"\b[0-9a-f]{40}\b"), "<UDID>"),
    ("path-home", re.compile(r"/Users/[^/\s\"',]+"), "/Users/<user>"),
    ("path-mobile", re.compile(r"/private/var/mobile/[^\s\"'<>]*"),
     "/private/var/mobile/<redacted>"),
]

_REDACT_KEYS = (
    "udid", "uniqueDeviceID", "uniqueChipID", "serialNumber", "SerialNumber",
    "crashReporterKey", "systemID", "provisioningUDID", "deviceIdentifierForVendor",
    "activationIdentifier", "internationalMobileEquipmentIdentity",
    "integratedCircuitCardIdentifier", "BluetoothAddress", "WiFiAddress",
    "EthernetMacAddress", "chipID", "ECID",
)
_REDACT_KEYS_LOWER = {key.lower() for key in _REDACT_KEYS}


def redact_text(text):
    """Redact identifiers from a string. Returns (clean_text, {rule: count})."""
    counts = {}
    for name, pattern, repl in _REDACT_RULES:
        text, n = pattern.subn(repl, text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts


def redact_obj(obj):
    """Recursively blank sensitive plist/JSON keys (case-insensitive).

    Returns (obj, n_redacted). Keys are matched case-insensitively: plists use
    'SerialNumber' while crash JSON uses 'serialNumber', and both must go.
    """
    replaced = 0

    def walk(node):
        nonlocal replaced
        if isinstance(node, dict):
            for key in list(node.keys()):
                if str(key).lower() in _REDACT_KEYS_LOWER:
                    if node[key] not in ("", None):
                        replaced += 1
                    node[key] = "<redacted>"
                else:
                    walk(node[key])
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return obj, replaced


def redact(text, counts=None):
    text, new_counts = redact_text(text)
    if counts is not None:
        for key, value in new_counts.items():
            counts[key] = counts.get(key, 0) + value
    return text


# ------------------------------------------------------------------- scanning


def scan_blob(text):
    """Find MTE markers in text. Returns {label: (count, class)}."""
    found = {}
    for label, pattern, klass in MTE_SIGNATURES:
        count = len(re.findall(pattern, text))
        if count:
            found[label] = (count, klass)
    return found


def scan_codes(text):
    """Pick out MTE exception codes mentioned in a report.

    Crash logs print them zero-padded (0x0000000000000106) and docs print
    them short (0x106); both count.
    """
    hits = []
    for code, meaning in MTE_EXCEPTION_CODES.items():
        digits = code[2:]
        if re.search(r"0x0*%s\b" % digits, text):
            hits.append((code, meaning))
    return hits


# --------------------------------------------------------------- .ips parsing


def load_report(path):
    """Load an .ips/.panic file.

    Modern .ips files are two JSON documents: a one-line header and the
    body. Legacy files are plain text. Returns a dict with the raw text,
    the parsed body if any, and the header if any.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()
    header, body = None, None
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        first_nl = raw.find("\n")
        if first_nl != -1:
            try:
                header = json.loads(raw[:first_nl])
            except ValueError:
                header = None
            try:
                body = json.loads(raw[first_nl:])
            except ValueError:
                body = None
    return {"path": path, "raw": raw, "header": header, "body": body}


def _format_codes(exc):
    codes = exc.get("codes")
    if isinstance(codes, str) and codes.strip():
        return codes.strip()
    raw = exc.get("rawCodes")
    if isinstance(raw, list) and raw:
        return ", ".join("0x%016x" % value if isinstance(value, int) else str(value)
                         for value in raw[:2])
    return "?"


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def summarize_report(report):
    """Extract the fields the corpus entries keep: exception, termination,
    region, top frames, process identity. Tolerant of format differences:
    every shape here is attacker-free input but not under our control
    (crash, panic, stacks and legacy reports all land in the same folder)."""
    body = _as_dict(report.get("body"))
    header = _as_dict(report.get("header"))
    raw = report.get("raw") or ""

    panic = body.get("panicString") or ""
    bug_type = str(body.get("bug_type") or header.get("bug_type") or "")
    if panic:
        kind = "panic"
    elif bug_type == "288":
        kind = "stacks"
    else:
        kind = "crash"

    process = (header.get("app_name") or body.get("procName")
               or body.get("product") or "")
    if not process and panic:
        process = "panic: " + panic.strip().splitlines()[0][:60]
    out = {
        "path": report.get("path"),
        "kind": kind,
        "process": process or "?",
        "timestamp": header.get("timestamp") or body.get("captureTime")
                     or body.get("date") or "?",
    }

    exc = _as_dict(body.get("exception"))
    out["exception_type"] = exc.get("type") or ("PANIC" if panic else "?")
    out["exception_codes"] = _format_codes(exc)
    subtype = exc.get("subtype") or exc.get("signal") or ""
    if not subtype:
        m = re.search(r"Exception Subtype:\s*(.+)", raw)
        subtype = m.group(1).strip() if m else "?"
    out["exception_subtype"] = subtype
    out["signal"] = exc.get("signal") or ""

    term = _as_dict(body.get("termination"))
    namespace = term.get("namespace") or ""
    code = term.get("code")
    out["termination"] = ("%s code %s" % (namespace, code)) if namespace else "?"
    if not namespace:
        m = re.search(r"Termination Reason:\s*Namespace (\S+), Code (\d+)", raw)
        if m:
            out["termination"] = "%s code %s" % (m.group(1), m.group(2))
    out["mte_state"] = (body.get("mteState") or exc.get("mteState")
                        or term.get("mteState")
                        or _grep(raw, r"[Mm]teState:?\s*[\"']?(\w+)"))
    out["vm_region"] = (_as_dict(body.get("vmRegionInfo")) or
                        _grep(raw, r"VM Region Info:\s*(.+)"))

    images = _as_list(body.get("usedImages"))
    threads = _as_list(body.get("threads"))
    frames = []
    faulting = body.get("faultingThread")
    if isinstance(faulting, int) and 0 <= faulting < len(threads):
        frames = _as_list(_as_dict(threads[faulting]).get("frames"))
    out["top_frames"] = []
    for frame in frames[:8]:
        if not isinstance(frame, dict):
            out["top_frames"].append(str(frame))
            continue
        index = frame.get("imageIndex")
        image = "?"
        if isinstance(index, int) and 0 <= index < len(images):
            image = _as_dict(images[index]).get("name") or "?"
        else:
            image = frame.get("image") or "?"
        symbol = frame.get("symbol")
        if not symbol:
            offset = frame.get("imageOffset")
            symbol = "+0x%x" % offset if isinstance(offset, int) else "?"
        out["top_frames"].append("%s  %s" % (image, symbol))
    if not out["top_frames"]:
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d+)\s+(\S+)\s+0x[0-9a-f]+\s+(\S+)", line)
            if m:
                out["top_frames"].append("%s  %s" % (m.group(2), m.group(3)))
            if len(out["top_frames"]) >= 8:
                break
    return out


def _grep(text, pattern):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ""


def analyse(path):
    """Full analysis of one report: summary + MTE findings."""
    report = load_report(path)
    summary = summarize_report(report)
    findings = scan_blob(report["raw"])
    summary["findings"] = findings
    summary["is_mte"] = bool(findings)
    summary["classes"] = sorted({klass for _, klass in findings.values()})
    return summary


# --------------------------------------------------------------- output utils


def write_atomic(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def corpus_entry(summary, redacted=True):
    """Render a findings doc entry in the repo's corpus style."""
    lines = []
    lines.append("### %s (%s)" % (summary["process"], summary["timestamp"]))
    lines.append("")
    lines.append("Source: `%s`" % (os.path.basename(summary["path"] or "?")))
    lines.append("kind: %s" % summary.get("kind", "crash"))
    lines.append("classes: %s" % (", ".join(summary["classes"]) or "none"))
    lines.append("")
    lines.append("    Exception Type:    %s (%s)"
                 % (summary["exception_type"], summary["signal"]))
    lines.append("    Exception Subtype: %s" % summary["exception_subtype"])
    lines.append("    Exception Codes:   %s" % summary["exception_codes"])
    lines.append("    Termination Reason: %s" % summary["termination"])
    if summary["mte_state"]:
        lines.append("    mteState:          %s" % summary["mte_state"])
    if summary["vm_region"]:
        lines.append("    Region:            %s" % summary["vm_region"])
    if summary["top_frames"]:
        lines.append("")
        lines.append("    faulting thread, top frames:")
        for idx, frame in enumerate(summary["top_frames"]):
            lines.append("    %d  %s" % (idx, frame))
    lines.append("")
    lines.append("findings: " + ", ".join(
        "%s x%d (%s)" % (label, count, klass)
        for label, (count, klass) in sorted(summary["findings"].items())
    ) or "findings: none")
    lines.append("")
    return "\n".join(lines)
