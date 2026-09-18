#!/usr/bin/env python3
"""Scan crash reports for MTE signatures, optionally pulling them off a device.

Usage:
    python3 scripts/mte_crash_scan.py <file-or-dir> [...]      # scan local
    python3 scripts/mte_crash_scan.py --device [UDID]          # pull + scan
    python3 scripts/mte_crash_scan.py --device --keep          # keep on device

Options:
    --device [UDID]   pull reports from a connected device with
                      idevicecrashreport (needs a trusted, unlocked device)
    --keep            do not remove the reports from the device
    --all             also list reports with no MTE signature
    --emit DIR        write corpus-style entries for every MTE hit into DIR
    --json            print machine readable output
    --no-anonymize    skip redaction (only for local inspection)

Exit codes: 0 = ran, at least one MTE report found; 1 = ran, no MTE report;
2 = could not run (no tool, no device, bad path).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import contrib_common as cc  # noqa: E402

REPORT_SUFFIXES = (".ips", ".panic", ".crash", ".txt")
PULL_DIR = os.path.join("contributions", "_pulled-crashes")


def find_reports(paths):
    found = []
    for path in paths:
        if os.path.isfile(path):
            found.append(path)
        elif os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in files:
                    if name.endswith(REPORT_SUFFIXES):
                        found.append(os.path.join(root, name))
        else:
            print("skip: %s does not exist" % path, file=sys.stderr)
    return sorted(found)


def pull_from_device(udid, keep):
    if not shutil.which("idevicecrashreport"):
        print("idevicecrashreport not found (install libimobiledevice-utils)",
              file=sys.stderr)
        return 2
    dest = PULL_DIR
    os.makedirs(dest, exist_ok=True)
    cmd = ["idevicecrashreport"]
    if udid:
        cmd += ["-u", udid]
    if keep:
        cmd.append("-k")
    cmd.append(dest)
    print("running: %s" % " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        print("idevicecrashreport failed: %s" % (result.stderr.strip() or
                                                 "exit %d" % result.returncode),
              file=sys.stderr)
        print("check: device plugged in, unlocked, tap Trust, usbmuxd running",
              file=sys.stderr)
        return 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="report files or directories")
    parser.add_argument("--device", nargs="?", const="", default=None,
                        help="pull from a connected device (optional UDID)")
    parser.add_argument("--keep", action="store_true",
                        help="do not remove pulled reports from the device")
    parser.add_argument("--all", action="store_true", help="list clean reports too")
    parser.add_argument("--emit", metavar="DIR", help="write corpus entries here")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-anonymize", action="store_true")
    args = parser.parse_args(argv)

    if args.device is not None:
        rc = pull_from_device(args.device or None, args.keep)
        if rc != 0:
            return rc
        args.paths.append(PULL_DIR)

    if not args.paths:
        parser.print_help()
        return 2

    reports = find_reports(args.paths)
    if not reports:
        print("no .ips/.panic/.crash files found in: %s" % ", ".join(args.paths),
              file=sys.stderr)
        return 2

    results = []
    hits = 0
    for path in reports:
        try:
            summary = cc.analyse(path)
        except Exception as exc:  # keep going, one bad file must not stop the run
            print("failed to parse %s: %s" % (path, exc), file=sys.stderr)
            continue
        results.append(summary)
        if summary["is_mte"]:
            hits += 1

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print("%d report(s) scanned, %d with MTE markers\n" % (len(results), hits))
        for summary in results:
            if not summary["is_mte"] and not args.all:
                continue
            flag = "MTE" if summary["is_mte"] else " - "
            print("[%s] %-28s %s" % (flag, summary["process"], os.path.basename(summary["path"])))
            print("      kind: %s | %s | %s | %s" % (summary.get("kind", "crash"),
                                                     summary["exception_type"],
                                                     summary["exception_subtype"],
                                                     summary["termination"]))
            if summary["mte_state"]:
                print("      mteState: %s   codes: %s" % (summary["mte_state"],
                                                          summary["exception_codes"]))
            for label, (count, klass) in sorted(summary["findings"].items()):
                print("      - %-32s x%-3d (%s)" % (label, count, klass))
            for idx, frame in enumerate(summary["top_frames"][:4]):
                print("      %d %s" % (idx, frame))
            print()

    if args.emit and hits:
        os.makedirs(args.emit, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out = os.path.join(args.emit, "mte-hits-%s.md" % stamp)
        chunks = ["# MTE crash hits (%s)\n" % stamp,
                  "Generated by scripts/mte_crash_scan.py. Review before "
                  "committing: names and paths are redacted, stack frames are "
                  "not.\n"]
        for summary in results:
            if not summary["is_mte"]:
                continue
            entry = cc.corpus_entry(summary)
            if not args.no_anonymize:
                entry, counts = cc.redact_text(entry)
                if counts:
                    entry += "\nredacted: " + ", ".join(
                        "%s x%d" % (k, v) for k, v in sorted(counts.items())) + "\n"
            chunks.append(entry)
        cc.write_atomic(out, "\n".join(chunks))
        print("wrote %s" % out)

    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
