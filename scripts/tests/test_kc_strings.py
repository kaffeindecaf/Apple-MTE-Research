#!/usr/bin/env python3
"""Tests for kc_strings.py: string inventory + the ADRP/ADD xref matcher.

The xref test does not depend on clang or on any Apple binary: it builds a
minimal 64-bit Mach-O in memory whose __text contains an ADRP+ADD pair that
forms the address of a string in __cstring. The instruction encodings are
produced by the small encoders below, which are in turn round-tripped through
capstone so a wrong encoding cannot silently pass.
"""

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
sys.path.insert(0, SCRIPTS)

import kc_strings  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
X86_THREAD_STATE64 = 0
VM_PROT_ALL = 7

TEXT_VM = 0x100000000
TEXT_SIZE = 0x4000
DATA_VM = 0x100004000
CSTRING_VM = DATA_VM


def encode_adrp(rd, target, pc):
    """ADRP Xd, target_page.

    Encoding: op(1) bit31 | immlo bits30-29 (= delta[1:0]) | 10000 bits28-24 |
    immhi bits23-5 (= delta[20:2]) | Rd.
    """
    assert rd < 32
    page_pc = pc & ~0xFFF
    page_target = target & ~0xFFF
    delta = (page_target - page_pc) >> 12
    assert -0x100000 <= delta < 0x100000, "adrp range"
    imm = delta & 0x1FFFFF
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    word = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
    return struct.pack("<I", word)


def encode_add_imm(rd, rn, imm, shift12=False):
    """ADD Xd, Xn, #imm{, LSL #12}."""
    assert 0 <= imm <= 0xFFF
    word = 0x91000000 | ((1 if shift12 else 0) << 22) | (imm << 10) | (rn << 5) | rd
    return struct.pack("<I", word)


def build_fixture(cstring_text="XREFTEST-STRING-0123456789"):
    """Return (file_bytes, text_vm, string_vm, text_file_offset)."""
    # layout: header | seg cmd + 2 sections | __text | __cstring
    header_size = 32
    seg_cmd_size = 72 + 80 * 2
    cmds_size = seg_cmd_size
    text_off = header_size + cmds_size
    string_off = text_off + TEXT_SIZE

    string_vm = CSTRING_VM
    # the pair we want the matcher to find
    code = encode_adrp(8, string_vm, TEXT_VM)
    code += encode_add_imm(0, 8, string_vm - (string_vm & ~0xFFF))
    code += struct.pack("<I", 0xD65F03C0)  # ret
    text = code + b"\x1f\x20\x03\xd5" * ((TEXT_SIZE - len(code)) // 4)

    out = bytearray()
    # mach_header_64 is 32 bytes: magic, cputype, cpusubtype, filetype,
    # ncmds, sizeofcmds, flags, reserved
    out += struct.pack("<IiiIIIII", MH_MAGIC_64, 0x0100000C, 2, 0, 1, cmds_size, 0, 0)
    # LC_SEGMENT_64 with two sections
    seg = struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, seg_cmd_size, b"__TEXT",
                      TEXT_VM, DATA_VM + len(cstring_text.encode()) - TEXT_VM, 0,
                      string_off + len(cstring_text), VM_PROT_ALL, VM_PROT_ALL, 2, 0)
    def section(name, segname, addr, size, offset):
        return struct.pack("<16s16sQQIIIIIIII", name, segname, addr, size, offset,
                           3, 0, 0, 0, 0, 0, 0)
    seg += section(b"__text", b"__TEXT", TEXT_VM, TEXT_SIZE, text_off)
    seg += section(b"__cstring", b"__TEXT", string_vm, len(cstring_text), string_off)
    out += seg
    assert len(out) == text_off
    out += text
    out += cstring_text.encode()
    return bytes(out), TEXT_VM, string_vm, text_off


class EncoderTests(unittest.TestCase):
    def test_adrp_encoding_round_trips_through_capstone(self):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        pc = 0x100001234
        target = 0x10000AB00
        insns = list(md.disasm(encode_adrp(8, target, pc), pc))
        self.assertEqual(len(insns), 1)
        self.assertEqual(insns[0].mnemonic, "adrp")
        self.assertEqual(insns[0].op_str, "x8, #0x%x" % (target & ~0xFFF))
        insns = list(md.disasm(encode_add_imm(0, 8, 0xAB0), 0))
        self.assertEqual(insns[0].op_str, "x0, x8, #0xab0")


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.blob, self.text_vm, self.string_vm, self.text_off = build_fixture()
        self.path = os.path.join("/tmp", "kc_strings_fixture.macho")
        with open(self.path, "wb") as handle:
            handle.write(self.blob)

    def test_fixture_parses_and_lists_the_string(self):
        entries = list(kc_strings.iter_strings(self.blob, min_len=6))
        texts = [entry["text"] for entry in entries]
        self.assertIn("XREFTEST-STRING-0123456789", texts)
        entry = [e for e in entries if e["text"].startswith("XREFTEST")][0]
        self.assertEqual(entry["vm"], self.string_vm)

    def test_xref_finds_the_adrp_add_pair(self):
        hits, targets = kc_strings.xrefs(self.blob, "XREFTEST-STRING")
        self.assertEqual(len(targets), 1)
        self.assertEqual(len(hits), 1)
        # the match is reported on the instruction that completes the pair,
        # so the adrp sits immediately before it
        self.assertEqual(hits[0]["at"], self.text_vm + 4)
        self.assertEqual(hits[0]["how"], "adrp+add")
        self.assertEqual(hits[0]["string_vm"], self.string_vm)

    def test_reported_address_is_the_second_half_of_an_adrp_add(self):
        import capstone
        hits, _targets = kc_strings.xrefs(self.blob, "XREFTEST-STRING")
        pair = self.blob[self.text_off:self.text_off + 8]
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        insns = list(md.disasm(pair, self.text_vm))
        self.assertEqual([insn.mnemonic for insn in insns], ["adrp", "add"])
        self.assertEqual(insns[1].address, hits[0]["at"])

    def test_xref_reports_nothing_for_absent_string(self):
        hits, targets = kc_strings.xrefs(self.blob, "NOT-PRESENT-ANYWHERE")
        self.assertEqual(hits, [])
        self.assertEqual(targets, [])

    def test_cli_xref_exit_code(self):
        self.assertEqual(kc_strings.main(["xref", self.path, "XREFTEST-STRING"]), 0)
        self.assertEqual(kc_strings.main(["strings", self.path, "XREFTEST"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
