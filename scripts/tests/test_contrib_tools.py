#!/usr/bin/env python3
"""Tests for the contribution tools.

    python3 scripts/tests/test_contrib_tools.py

The .ips fixtures are reconstructed from signature blocks already published in
docs/09-mte-bugs-field.md (Futurae S25) and from real report shapes seen in the
wild, so the parser is exercised against the formats it must handle without
shipping anyone's device data.

Optional integration test: set REPO_TEST_KC=/path/to/kernelcache to also census
a real kernelcache (skipped silently when unset).
"""

import json
import os
import plistlib
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
sys.path.insert(0, SCRIPTS)

import contrib_common as cc  # noqa: E402
import mte_crash_scan  # noqa: E402
import mte_device_report  # noqa: E402
import mte_insn_census  # noqa: E402


def mte_ips_text():
    """A modern two-document .ips report carrying the published Futurae
    MTE signature (EXC_ARM_MTE_TAGCHECK_FAIL, MTE_FAIL 262)."""
    header = {
        "app_name": "FuturaeKitExample",
        "timestamp": "2026-06-03 06:22:49.00 +0200",
        "app_version": "1.0",
        "bug_type": "309",
        "os_version": "iPhone OS 26.5.1 (23F81)",
    }
    body = {
        "procName": "FuturaeKitExample",
        "captureTime": "2026-06-03 06:22:49.00 +0200",
        "modelCode": "iPhone18,5",
        "osVersion": {"train": "iPhone OS 26.5.1", "build": "23F81"},
        "exception": {
            "type": "EXC_BAD_ACCESS",
            "signal": "SIGKILL",
            "codes": "0x0000000000000106, 0x0000000d6514c3d8",
            "subtype": "EXC_ARM_MTE_TAGCHECK_FAIL at 0x0000000d6514c3d8",
        },
        "termination": {"namespace": "MTE_FAIL", "code": 262,
                        "indicator": "Namespace MTE_FAIL, Code 262"},
        "mteState": "enabled",
        "faultingThread": 0,
        "vmRegionInfo": "0x104c98000-0x104caa000 MALLOC_SMALL 80K rw-/rwx",
        "usedImages": [{"name": "FuturaeKit"}, {"name": "libsystem_kernel.dylib"}],
        "threads": [{"frames": [
            {"imageIndex": 0, "symbol": "getEnumTagSinglePayload for Bag"},
            {"imageIndex": 0, "symbol": "protocol witness for Index.initializeWithCopy"},
            {"imageIndex": 1, "symbol": "abort"},
        ]}],
        "crashReporterKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "systemID": "00008110-000408462E00A01E",
    }
    return json.dumps(header) + "\n" + json.dumps(body) + "\n"


def legacy_ips_text():
    """A legacy plain-text report with the same signature block."""
    return """Incident Identifier: 12345678-ABCD-EF01-2345-6789ABCDEF01
CrashReporter Key:   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hardware Model:      iPhone18,5
Process:             FuturaeKitExample [1234]
OS Version:          iPhone OS 26.5.1 (23F81)
Exception Type:    EXC_BAD_ACCESS (SIGKILL)
Exception Subtype: EXC_ARM_MTE_TAGCHECK_FAIL at 0x0000000d6514c3d8
Exception Codes:   0x0000000000000106, 0x0000000d6514c3d8
Termination Reason: Namespace MTE_FAIL, Code 262
VM Region Info: 0x104c98000-0x104caa000 MALLOC_SMALL 80K rw-/rwx SM=ZER
mteState: enabled

Thread 0 Crashed:
0   FuturaeKit   0x0000000104c98000 getEnumTagSinglePayload for Bag
1   FuturaeKit   0x0000000104c98100 Index.initializeWithCopy
"""


def clean_ips_text():
    """A report with no MTE markers (control device shape)."""
    header = {"app_name": "SomeApp", "timestamp": "2026-09-05 17:30:15.00 +0200",
              "bug_type": "309"}
    body = {
        "procName": "SomeApp",
        "exception": {"type": "EXC_CRASH", "signal": "SIGABRT",
                      "codes": "0x0000000000000000, 0x0000000000000000",
                      "rawCodes": [0, 0]},
        "termination": {"namespace": "SIGNAL", "code": 6},
        "faultingThread": 0,
        "usedImages": [{"name": "libsystem_kernel.dylib"}],
        "threads": [{"frames": [{"imageIndex": 0,
                                 "symbol": "__pthread_kill"}]}],
    }
    return json.dumps(header) + "\n" + json.dumps(body) + "\n"


class TempFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path


class DeviceVerdictTests(unittest.TestCase):
    def test_iphone18_is_mte_capable(self):
        family, chip, capable, _note = cc.device_verdict("iPhone18,1")
        self.assertIn("17", family)
        self.assertEqual(chip, "A19 (T8150)")
        self.assertIs(capable, True)

    def test_tag_storage_note_on_later_iphone18(self):
        _family, _chip, capable, note = cc.device_verdict("iPhone18,5")
        self.assertIs(capable, True)
        self.assertIn("tag storage", note)

    def test_pre_mie_devices_are_controls(self):
        for product in ("iPhone14,7", "iPhone12,8", "iPhone17,2"):
            with self.subTest(product=product):
                _family, _chip, capable, _note = cc.device_verdict(product)
                self.assertIs(capable, False)

    def test_mac_and_unknown_are_not_guessed(self):
        _family, _chip, capable, note = cc.device_verdict("Mac16,1")
        self.assertIsNone(capable)
        self.assertIn("M5", note)
        _family, _chip, capable, note = cc.device_verdict("iBridge2,1")
        self.assertIsNone(capable)
        self.assertIn("not in the table", note)

    def test_empty_product_type(self):
        _family, _chip, capable, note = cc.device_verdict("")
        self.assertIsNone(capable)
        self.assertIn("no ProductType", note)


class RedactionTests(unittest.TestCase):
    def test_udid_and_home_paths_are_scrubbed(self):
        text = ("udid 00008110-000408462E00A01E in "
                "/Users/kaffein/Library/Logs and 40 hex "
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        clean, counts = cc.redact_text(text)
        self.assertNotIn("00008110-000408462E00A01E", clean)
        self.assertNotIn("kaffein", clean)
        self.assertIn("<UDID>", clean)
        self.assertGreaterEqual(counts["udid"], 1)

    def test_sensitive_keys_are_blanked_recursively(self):
        obj = {"serialNumber": "F17ABC123", "nested": {"crashReporterKey": "deadbeef"},
               "keep": "iPhone18,5"}
        clean, replaced = cc.redact_obj(obj)
        self.assertEqual(replaced, 2)
        self.assertEqual(clean["serialNumber"], "<redacted>")
        self.assertEqual(clean["nested"]["crashReporterKey"], "<redacted>")
        self.assertEqual(clean["keep"], "iPhone18,5")

    def test_key_matching_is_case_insensitive(self):
        # ideviceinfo plists use SerialNumber/UniqueChipID, crash JSON uses
        # serialNumber: both spellings must be blanked
        obj = {"SerialNumber": "F17ABC123", "UniqueChipID": 12345678901234,
               "ECID": 9, "DeviceClass": "iPhone"}
        clean, replaced = cc.redact_obj(obj)
        self.assertEqual(replaced, 3)
        self.assertEqual(clean["DeviceClass"], "iPhone")


class ScanTests(unittest.TestCase):
    def test_scan_blob_finds_signatures_with_classes(self):
        found = cc.scan_blob("EXC_ARM_MTE_TAGCHECK_FAIL ... MTE_FAIL code 262 "
                             "mteState: enabled")
        self.assertEqual(found["EXC_ARM_MTE_TAGCHECK_FAIL"][1], "tag-check-fault")
        self.assertIn("MTE_FAIL", found)
        self.assertEqual(found["mteState enabled"][1], "mte-state")

    def test_exception_codes_are_recognised(self):
        codes = dict(cc.scan_codes("Exception Codes: 0x0000000000000106, 0x107"))
        self.assertIn("0x106", codes)
        self.assertIn("0x107", codes)


class IpsParsingTests(TempFixture):
    def test_modern_report_parses_and_is_flagged(self):
        path = self.write("mte.ips", mte_ips_text())
        summary = cc.analyse(path)
        self.assertTrue(summary["is_mte"])
        self.assertEqual(summary["kind"], "crash")
        self.assertEqual(summary["termination"], "MTE_FAIL code 262")
        self.assertEqual(summary["mte_state"], "enabled")
        self.assertIn("EXC_ARM_MTE_TAGCHECK_FAIL", summary["exception_subtype"])
        self.assertIn("0x0000000000000106", summary["exception_codes"])
        self.assertIn("FuturaeKit  getEnumTagSinglePayload for Bag",
                      summary["top_frames"])

    def test_legacy_report_falls_back_to_text(self):
        path = self.write("legacy.ips", legacy_ips_text())
        summary = cc.analyse(path)
        self.assertTrue(summary["is_mte"])
        self.assertEqual(summary["termination"], "MTE_FAIL code 262")
        self.assertTrue(summary["top_frames"])
        self.assertIn("MALLOC_SMALL", summary["vm_region"])

    def test_clean_report_is_not_flagged(self):
        path = self.write("clean.ips", clean_ips_text())
        summary = cc.analyse(path)
        self.assertFalse(summary["is_mte"])
        self.assertEqual(summary["exception_type"], "EXC_CRASH")

    def test_panic_and_stacks_shapes_do_not_crash(self):
        # panic reports carry panicString and no exception/threads keys;
        # "stacks" reports (bug_type 288) carry processByPid instead
        panic = {"panicString": "panic(cpu 3 caller 0xfffffff0070abc12): "
                                "termination reason MTE_FAIL (code 262)",
                 "bug_type": "210"}
        stacks = {"bug_type": "288", "product": "iPhone12,8",
                  "processByPid": {"1": "launchd"}, "kernel": {}}
        for name, body in (("panic.ips", panic), ("stacks.ips", stacks)):
            with self.subTest(name=name):
                path = self.write(name, json.dumps({"bug_type": body["bug_type"]})
                                  + "\n" + json.dumps(body))
                summary = cc.analyse(path)
                self.assertIn(summary["kind"], ("panic", "stacks"))
                if name == "panic.ips":
                    self.assertEqual(summary["kind"], "panic")
                    self.assertTrue(summary["is_mte"])

    def test_corpus_entry_keeps_the_signature_block(self):
        path = self.write("mte.ips", mte_ips_text())
        entry = cc.corpus_entry(cc.analyse(path))
        for needle in ("Exception Subtype:", "Exception Codes:",
                       "Termination Reason: MTE_FAIL code 262",
                       "mteState:", "faulting thread, top frames"):
            self.assertIn(needle, entry)


class DeviceReportTests(TempFixture):
    """Offline device-report path, using an ideviceinfo-shaped plist fixture.

    The fixture keys mirror what `ideviceinfo -x` returns; no device data is
    involved.
    """

    def plist_fixture(self, product_type="iPhone18,5", extra=None):
        info = {
            "ProductType": product_type,
            "HardwareModel": "D93AP",
            "HardwarePlatform": "t8150",
            "ProductVersion": "26.5.1",
            "BuildVersion": "23F81",
            "CPUArchitecture": "arm64e",
            "DeviceClass": "iPhone",
            "ModelNumber": "MQ1A2",
            "RegionInfo": "LL/A",
            "UniqueChipID": 12345678901234,
            "SerialNumber": "F17ABCDEFGHI",
            "UniqueDeviceID": "00008110-000408462E00A01E",
        }
        if extra:
            info.update(extra)
        return self.write("info.plist", plistlib.dumps(info).decode())

    def test_report_is_written_and_redacted(self):

        plist = self.plist_fixture()
        out = os.path.join(self.tmp.name, "contrib")
        rc = mte_device_report.main(["--plist", plist, "--out", out])
        self.assertEqual(rc, 0)
        bundles = os.listdir(out)
        self.assertEqual(len(bundles), 1)
        self.assertIn("iPhone18,5", bundles[0])
        report = open(os.path.join(out, bundles[0], "device-report.md"),
                      encoding="utf-8").read()
        self.assertIn("MTE/MIE capable: yes", report)
        self.assertIn("tag storage", report)
        self.assertNotIn("00008110-000408462E00A01E", report)
        self.assertNotIn("F17ABCDEFGHI", report)
        self.assertNotIn("12345678901234", report)
        self.assertIn("HardwarePlatform: t8150", report)
        self.assertIn("## Submitting this report", report)
        self.assertIn("git checkout -b", report)

    def test_control_device_gets_control_asks(self):

        plist = self.plist_fixture(product_type="iPhone14,7")
        out = os.path.join(self.tmp.name, "contrib")
        self.assertEqual(mte_device_report.main(["--plist", plist, "--out", out]), 0)
        bundle = os.listdir(out)[0]
        report = open(os.path.join(out, bundle, "device-report.md"),
                      encoding="utf-8").read()
        self.assertIn("MTE/MIE capable: no", report)
        self.assertIn("control data", report)


class CliTests(TempFixture):
    def test_clean_corpus_exits_one_and_mte_corpus_exits_zero(self):
        clean = self.write("clean.ips", clean_ips_text())
        self.assertEqual(mte_crash_scan.main([clean]), 1)
        mte = self.write("mte.ips", mte_ips_text())
        emit = os.path.join(self.tmp.name, "out")
        self.assertEqual(mte_crash_scan.main([mte, "--emit", emit]), 0)
        produced = os.listdir(emit)
        self.assertEqual(len(produced), 1)
        with open(os.path.join(emit, produced[0]), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("MTE_FAIL code 262", text)
        self.assertNotIn("00008110-000408462E00A01E", text)

    def test_missing_path_exits_two(self):
        self.assertEqual(mte_crash_scan.main([os.path.join(self.tmp.name, "nope")]), 2)

    def test_census_rejects_junk_with_a_reason(self):
        junk = self.write("junk.bin", "not a mach-o at all")
        self.assertEqual(mte_insn_census.main([junk]), 2)

    def test_census_reports_compressed_payloads(self):
        blob = b"\x30\x84\x01\x0b" + b"IM4P" + b"\x16\x04krnl" + b"bvx2" + b"\0" * 64
        path = os.path.join(self.tmp.name, "compressed.kc")
        with open(path, "wb") as handle:
            handle.write(blob)
        with self.assertRaises(mte_insn_census.ParseError) as ctx:
            mte_insn_census.unwrap(blob)
        self.assertIn("LZFSE", str(ctx.exception))
        self.assertEqual(mte_insn_census.main([path]), 2)


class RealKernelcacheTests(unittest.TestCase):
    """Runs only when REPO_TEST_KC points at a real kernelcache."""

    def test_census_on_real_kernelcache(self):
        path = os.environ.get("REPO_TEST_KC")
        if not path or not os.path.exists(path):
            self.skipTest("REPO_TEST_KC not set")
        data = open(path, "rb").read()
        offset, _note, _desc = mte_insn_census.unwrap(data)
        result = mte_insn_census.census(data, offset)
        self.assertGreater(result["total_insns"], 0)
        self.assertGreater(len(result["units"]), 0)


PROBE_ASM = """.text
.globl _probe
_probe:
    irg  x1, x0
    stg  x1, [x0]
    ldg  x2, [x0]
    stzg x1, [x0]
    st2g x1, [x0]
    addg x0, x0, #16, #1
    subg x0, x0, #16, #2
    gmi  x3, x0, x1
    ret
"""


class InstructionDetectionTests(TempFixture):
    """The counter must see MTE instructions where they exist.

    Cross-compiles a probe object with clang (Mach-O arm64, no linker needed)
    and checks every instruction form the census looks for is counted. Skips
    when clang cannot emit Mach-O.
    """

    def test_probe_object_is_counted(self):
        import shutil
        import subprocess
        clang = shutil.which("clang")
        if not clang:
            self.skipTest("clang not available")
        asm = self.write("probe.S", PROBE_ASM)
        obj = os.path.join(self.tmp.name, "probe.o")
        result = subprocess.run(
            [clang, "-c", "-target", "arm64-apple-ios16.0",
             "-march=armv8.5-a+memtag", "-o", obj, asm],
            capture_output=True, text=True)
        if result.returncode != 0:
            self.skipTest("clang cannot cross-compile to Mach-O arm64: %s"
                          % result.stderr.strip()[:120])
        data = open(obj, "rb").read()
        offset, _note, _desc = mte_insn_census.unwrap(data)
        census = mte_insn_census.census(data, offset)
        for mnemonic in ("irg", "stg", "ldg", "stzg", "st2g", "addg", "subg",
                         "gmi"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(census["totals"][mnemonic], 1,
                                 "%s not counted" % mnemonic)
        self.assertEqual(census["mte_insns"], 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
