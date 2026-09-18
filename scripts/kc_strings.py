#!/usr/bin/env python3
"""String inventory and string cross-references for a kernelcache or Mach-O.

Shipped kernelcaches are stripped (LC_SYMTAB nsyms = 0), so symbol names are
not available. What is available is the string/name table and the code that
refers to it, which is what this tool reads.

Usage:
    kc_strings.py strings <file> [PATTERN] [--min 6] [--section __cstring]
    kc_strings.py xref <file> <SUBSTRING> [--max 20] [--kext PATTERN]
    kc_strings.py diff <file-a> <file-b> [PATTERN]

    strings   list printable runs with kext/section/offset/VM address
    xref      find code that materialises a string address (ADRP+ADD/LDR),
              i.e. the function that uses it
    diff      count the same pattern in two files (A19 vs A13, 26.x vs 27.x)

Requires capstone for xref. Exit codes: 0 = ran, 2 = could not parse.
"""

import argparse
import re
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mte_insn_census as mic  # noqa: E402

PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}")


def sections_of(data):
    """Yield (kext, section, base_vm, file_offset, size) for every section."""
    offset, note, _desc = mic.unwrap(data)
    for label, unit_off in mic.iter_macho_units(data, offset):
        try:
            sections, _symbols = mic.parse_macho(data, unit_off)
        except mic.ParseError:
            continue
        for section in sections:
            yield label, section


def iter_strings(data, min_len=6, section_filter=None, kext_filter=None):
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for label, section in sections_of(data):
        if section_filter and section["name"] != section_filter:
            continue
        if kext_filter and kext_filter.lower() not in label.lower():
            continue
        # skip zerofill sections (no data in the file): reading them would
        # produce strings from the Mach-O header at file offset 0
        if not section["size"] or not section["offset"]:
            continue
        if section["offset"] + section["size"] > len(data):
            continue
        blob = data[section["offset"]:section["offset"] + section["size"]]
        for match in pattern.finditer(blob):
            yield {
                "kext": label,
                "section": section["name"],
                "seg": section["seg"],
                "file_offset": section["offset"] + match.start(),
                "vm": section["addr"] + match.start(),
                "text": match.group().decode("ascii", "replace"),
            }


def find_string_vms(data, needle, min_len=6):
    """VM addresses of every string containing `needle`."""
    return [entry for entry in iter_strings(data, min_len)
            if needle in entry["text"]]


def xrefs(data, needle, max_hits=20, kext_filter=None):
    """Find code that materialises the address of a string containing needle.

    Two shapes are handled:
      ADRP + ADD   -> the address is formed directly (kernel-style code)
      ADRP + LDR   -> the address is loaded from a literal pointer slot
                      (darwin/dylib-style code); the slot gets a second hop

    Returns (hits, string_targets).
    """
    try:
        import capstone
    except ImportError:
        raise mic.ParseError("capstone is required: pip install capstone")

    targets = find_string_vms(data, needle)
    if not targets:
        return [], []
    ranges = [(entry["vm"], entry["vm"] + len(entry["text"]), entry)
              for entry in targets]

    # VM -> file offset map, so pointer slots can be read. Sections whose data
    # is not in the file (zerofill: offset 0) are skipped, otherwise a slot
    # lookup inside __bss reads the Mach-O header instead.
    vm_map = []
    for _label, section in sections_of(data):
        if section["size"] and section["offset"]:
            end = section["offset"] + section["size"]
            if end <= len(data):
                vm_map.append((section["addr"], section["addr"] + section["size"],
                               section["offset"], section["size"]))

    def read_u64(vm):
        for low, high, file_off, size in vm_map:
            if low <= vm < high and vm + 8 <= high:
                offset = file_off + (vm - low)
                if offset + 8 <= len(data):
                    return struct.unpack_from("<Q", data, offset)[0]
        return None

    def resolve_pointer(value):
        """Pointer slots are usually chained-fixup encoded: 36-bit offset
        (DYLD_CHAINED_PTR_64_OFFSET) or a plain 48-bit VM address. A candidate
        is accepted when it lands inside a section that exists in the file."""
        for mask in (0xFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            candidate = value & mask
            for low, high, _file_off, _size in vm_map:
                if low <= candidate < high:
                    return candidate
        return None

    def match(vm):
        for low, high, entry in ranges:
            if low <= vm < high:
                return entry
        return None

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    hits = []
    for label, section in sections_of(data):
        if section["name"] != "__text":
            continue
        if kext_filter and kext_filter.lower() not in label.lower():
            continue
        code = data[section["offset"]:section["offset"] + section["size"]]
        if not code:
            continue
        page_of_reg = {}
        ptr_of_reg = {}
        for insn in md.disasm(code, section["addr"]):
            operands = insn.operands
            if insn.mnemonic == "adrp" and len(operands) == 2:
                page_of_reg[operands[0].reg] = operands[1].imm
                ptr_of_reg.pop(operands[0].reg, None)
                continue
            slot_or_addr = None
            how = ""
            if insn.mnemonic == "add" and len(operands) == 3:
                base, imm = operands[1], operands[2]
                if (base.type == capstone.arm64.ARM64_OP_REG
                        and imm.type == capstone.arm64.ARM64_OP_IMM):
                    if base.reg in ptr_of_reg:
                        # table-referenced string: pointer from a slot + offset
                        slot_or_addr = ptr_of_reg[base.reg] + imm.imm
                        how = "ldr+add"
                    elif base.reg in page_of_reg:
                        slot_or_addr = page_of_reg[base.reg] + imm.imm
                        how = "adrp+add"
            elif insn.mnemonic in ("ldr", "ldrb") and len(operands) == 2:
                mem = operands[1]
                if (mem.type == capstone.arm64.ARM64_OP_MEM
                        and mem.mem.base in page_of_reg):
                    slot_or_addr = page_of_reg[mem.mem.base] + mem.mem.disp
                    how = "adrp+ldr slot"
            if slot_or_addr is None:
                continue
            entry = match(slot_or_addr)
            if entry is None and how == "adrp+ldr slot" and len(operands) == 2 \
                    and operands[0].type == capstone.arm64.ARM64_OP_REG:
                pointer = read_u64(slot_or_addr)
                if pointer is not None:
                    decoded = resolve_pointer(pointer)
                    if decoded is not None:
                        ptr_of_reg[operands[0].reg] = decoded
                        if match(decoded) is not None:
                            entry = match(decoded)
                            how = "adrp+ldr -> 0x%x" % decoded
            if entry is not None:
                hits.append({
                    "kext": label,
                    "at": insn.address,
                    "insn": "%s %s" % (insn.mnemonic, insn.op_str),
                    "string_vm": entry["vm"],
                    "string": entry["text"][:70],
                    "how": how,
                })
                if len(hits) >= max_hits:
                    return hits, targets
    return hits, targets


def cmd_strings(args):
    data = open(args.file, "rb").read()
    count = 0
    for entry in iter_strings(data, args.min, args.section, args.kext):
        if args.pattern and args.pattern.lower() not in entry["text"].lower():
            continue
        count += 1
        print("%-34s %-10s off=0x%-8x vm=0x%-12x %s"
              % (entry["kext"][:34], entry["section"], entry["file_offset"],
                 entry["vm"], entry["text"][:90]))
    print("\n%d string(s)" % count)
    return 0


def cmd_xref(args):
    data = open(args.file, "rb").read()
    hits, targets = xrefs(data, args.needle, args.max, args.kext)
    print("strings matching %r: %d at %s" % (args.needle, len(targets),
                                             [hex(t["vm"]) for t in targets[:6]]))
    if not hits:
        print("no code references found (string may be data-referenced or "
              "built by index, not by address)")
        return 0
    print("\n%d reference(s):" % len(hits))
    for hit in hits:
        print("  %-30s at 0x%-12x %-28s -> 0x%-12x %s"
              % (hit["kext"][:30], hit["at"], hit["insn"], hit["string_vm"],
                 hit["string"]))
    return 0


def cmd_diff(args):
    data_a = open(args.file_a, "rb").read()
    data_b = open(args.file_b, "rb").read()
    needles = [args.pattern] if args.pattern else None
    if needles:
        print("%-40s %10s %10s" % ("needle", os.path.basename(args.file_a)[:10],
                                   os.path.basename(args.file_b)[:10]))
        print("%-40s %10d %10d" % (needles[0], data_a.count(needles[0].encode()),
                                   data_b.count(needles[0].encode())))
        return 0
    strings_a = {entry["text"] for entry in iter_strings(data_a, args.min)}
    strings_b = {entry["text"] for entry in iter_strings(data_b, args.min)}
    only_a = sorted(strings_a - strings_b)
    only_b = sorted(strings_b - strings_a)
    print("strings: %d in A, %d in B, %d only in A, %d only in B"
          % (len(strings_a), len(strings_b), len(only_a), len(only_b)))
    print("\n--- only in %s (up to 40)" % os.path.basename(args.file_a))
    for text in only_a[:40]:
        print("   ", text[:100])
    print("\n--- only in %s (up to 40)" % os.path.basename(args.file_b))
    for text in only_b[:40]:
        print("   ", text[:100])
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_strings = sub.add_parser("strings")
    p_strings.add_argument("file")
    p_strings.add_argument("pattern", nargs="?")
    p_strings.add_argument("--min", type=int, default=6)
    p_strings.add_argument("--section")
    p_strings.add_argument("--kext")
    p_strings.set_defaults(func=cmd_strings)

    p_xref = sub.add_parser("xref")
    p_xref.add_argument("file")
    p_xref.add_argument("needle")
    p_xref.add_argument("--max", type=int, default=20)
    p_xref.add_argument("--kext")
    p_xref.set_defaults(func=cmd_xref)

    p_diff = sub.add_parser("diff")
    p_diff.add_argument("file_a")
    p_diff.add_argument("file_b")
    p_diff.add_argument("pattern", nargs="?")
    p_diff.add_argument("--min", type=int, default=8)
    p_diff.set_defaults(func=cmd_diff)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except mic.ParseError as exc:
        print("cannot parse %s: %s" % (getattr(args, "file", "?"), exc),
              file=sys.stderr)
        return 2
    except OSError as exc:
        print("cannot read: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
