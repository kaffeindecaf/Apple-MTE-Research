#!/usr/bin/env python3
"""Count MTE instructions in an arm64/arm64e Mach-O (kernelcache, kext, dylib).

This is the tool behind the "MTE instruction census" checklist item: numbers
you can paste into a PR without shipping Apple binaries. It understands
kernelcache filesets (LC_FILESET_ENTRY), so it reports per-kext counts.

Usage:
    python3 scripts/mte_insn_census.py kernelcache.kc
    python3 scripts/mte_insn_census.py kernelcache.kc --top 20 --csv out.csv
    python3 scripts/mte_insn_census.py kernelcache.kc --kext security
    python3 scripts/mte_insn_census.py Some.dylib --section __text

IM4P-wrapped kernelcaches are unwrapped automatically when the payload is
uncompressed. Compressed payloads (complzss / LZFSE) are reported with the
command to decompress first.

Needs capstone (pip install capstone). Exit codes: 0 = census written,
2 = could not parse (reason printed).
"""

import argparse
import bisect
import csv
import os
import struct
import sys
import time

MACHO_MAGICS = {
    0xFEEDFACF: "macho64-le",
    0xFEEDFACE: "macho32-le",
    0xCFFAEDFE: "macho64-be",
    0xCEFAEDFE: "macho32-be",
    0xCAFEBABE: "fat-be",
    0xBEBAFECA: "fat-le",
}

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_FILESET_ENTRY = 0x80000035

MTE_MNEMONICS = {
    "irg": "insert random tag (allocate)",
    "stg": "store allocation tag",
    "stzg": "store allocation tag, zero the granule",
    "st2g": "store allocation tag, two granules",
    "stz2g": "store allocation tag, zero two granules",
    "ldg": "load allocation tag",
    "stgm": "store allocation tags, range",
    "stzgm": "store allocation tags and zero, range",
    "ldgm": "load allocation tags, range",
    "gmi": "tag mask insert (into a pointer)",
    "addg": "add with tag adjustment",
    "subg": "subtract with tag adjustment",
    "dc gzva (memtag zero)": "data cache zero by VA (tag-aware zeroing)",
}
GZVA_LABEL = "dc gzva (memtag zero)"


class ParseError(Exception):
    pass


# ------------------------------------------------------------------ container


def unwrap(data):
    """Return (macho_offset, note, build_description)."""
    if len(data) < 4:
        raise ParseError("file too short")
    magic = struct.unpack("<I", data[:4])[0]
    if magic in MACHO_MAGICS:
        return 0, "raw Mach-O", ""
    im4p = data.find(b"IM4P")
    if im4p == -1:
        raise ParseError("not a Mach-O and no IM4P wrapper found")
    description = ""
    for marker in (b"krnl", b"rkrn", b"ibot", b"rdsk", b"dtre"):
        idx = data.find(marker, im4p, im4p + 256)
        if idx != -1:
            start = idx + 4 + 2
            chunk = data[start:start + 64]
            description = "".join(chr(byte) for byte in chunk
                                  if 32 <= byte < 127).strip()
            break
    for name, magic_bytes in (("LZFSE", b"bvx2"), ("LZFSE", b"bvxn"),
                              ("LZSS", b"complzss")):
        if data.find(magic_bytes, im4p) != -1:
            raise ParseError(
                "IM4P payload is %s-compressed. Decompress first, e.g.:\n"
                "  pyimg4 im4p extract -i <file> -o out.kc --lzfse\n"
                "  ipsw kernel extract <file>" % name)
    for offset in range(im4p, min(len(data) - 4, im4p + 2_000_000)):
        magic = struct.unpack("<I", data[offset:offset + 4])[0]
        if magic in (0xFEEDFACF, 0xCAFEBABE):
            return offset, "IM4P wrapper, uncompressed payload", description
    raise ParseError("IM4P wrapper found but no Mach-O payload located "
                     "(likely compressed)")


def read_slices(data, offset):
    """Slice offsets inside a container: fat slices, or just the one Mach-O."""
    magic = struct.unpack(">I", data[offset:offset + 4])[0]
    if MACHO_MAGICS.get(magic, "").startswith("fat"):
        count = struct.unpack(">I", data[offset + 4:offset + 8])[0]
        slices = []
        for index in range(count):
            base = offset + 8 + index * 20
            slices.append(struct.unpack(">I", data[base + 8:base + 12])[0])
        return slices
    return [offset]


def iter_macho_units(data, offset):
    """Yield (label, macho_offset) for a kernelcache fileset or a plain binary."""
    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    if magic != 0xFEEDFACF:
        raise ParseError("only 64-bit little-endian Mach-O is supported "
                         "(magic 0x%08x)" % magic)
    ncmds = struct.unpack("<I", data[offset + 16:offset + 20])[0]
    cmd_off = offset + 32
    units = []
    for _ in range(ncmds):
        if cmd_off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[cmd_off:cmd_off + 8])
        if cmd == LC_FILESET_ENTRY and cmdsize >= 32:
            file_off = struct.unpack("<Q", data[cmd_off + 16:cmd_off + 24])[0]
            id_off = struct.unpack("<I", data[cmd_off + 24:cmd_off + 28])[0]
            raw_name = data[cmd_off + id_off:cmd_off + cmdsize].split(b"\0")[0]
            if file_off and file_off + 4 <= len(data):
                units.append((raw_name.decode("utf-8", "replace"), file_off))
        cmd_off += cmdsize
    if not units:
        yield ("(binary)", offset)
        return
    for label, file_off in units:
        yield (label, file_off)


# ------------------------------------------------------------------- mach-o


def parse_macho(data, offset):
    """Return (sections, symbols) for one thin Mach-O."""
    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    if magic != 0xFEEDFACF:
        raise ParseError("nested Mach-O at 0x%x is not supported (magic 0x%08x)"
                         % (offset, magic))
    ncmds = struct.unpack("<I", data[offset + 16:offset + 20])[0]
    cmd_off = offset + 32
    sections = []
    symbols = []
    for _ in range(ncmds):
        if cmd_off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[cmd_off:cmd_off + 8])
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack("<I", data[cmd_off + 64:cmd_off + 68])[0]
            sect_off = cmd_off + 72
            for _s in range(nsects):
                sectname = data[sect_off:sect_off + 16].split(b"\0")[0].decode(
                    "utf-8", "replace")
                segname = data[sect_off + 16:sect_off + 32].split(b"\0")[0].decode(
                    "utf-8", "replace")
                addr, size = struct.unpack("<QQ", data[sect_off + 32:sect_off + 48])
                file_off = struct.unpack("<I", data[sect_off + 48:sect_off + 52])[0]
                sections.append({"seg": segname, "name": sectname, "addr": addr,
                                 "size": size, "offset": file_off})
                sect_off += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, _strsize = struct.unpack(
                "<IIII", data[cmd_off + 8:cmd_off + 24])
            for index in range(nsyms):
                base = symoff + index * 16
                if base + 16 > len(data):
                    break
                strx = struct.unpack("<I", data[base:base + 4])[0]
                n_type = data[base + 4]
                value = struct.unpack("<Q", data[base + 8:base + 16])[0]
                if n_type & 0x0E != 0x0E or not value:
                    continue  # keep N_SECT defined symbols only
                end = data.find(b"\0", stroff + strx)
                if end == -1:
                    continue
                name = data[stroff + strx:end].decode("utf-8", "replace")
                if name:
                    symbols.append((value, name))
        cmd_off += cmdsize
    symbols.sort()
    return sections, symbols


# ------------------------------------------------------------------- census


def census(data, offset, section_filter="__text", kext_filter=None,
           progress=False):
    try:
        import capstone
    except ImportError:
        raise ParseError("capstone is required: pip install capstone")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    totals = {name: 0 for name in MTE_MNEMONICS}
    totals[GZVA_LABEL] = 0
    total_insns = 0
    units = []
    all_symbols = {}

    for label, unit_off in iter_macho_units(data, offset):
        if kext_filter and kext_filter.lower() not in label.lower():
            continue
        try:
            sections, symbols = parse_macho(data, unit_off)
        except ParseError:
            continue
        unit_counts = {name: 0 for name in MTE_MNEMONICS}
        unit_counts[GZVA_LABEL] = 0
        unit_insns = 0
        sites = []
        for section in sections:
            if section["name"] != section_filter:
                continue
            code = data[section["offset"]:section["offset"] + section["size"]]
            if not code:
                continue
            # capstone stops at the first word it cannot decode (padding,
            # literal pools, jump tables inside __text). Resync 4 bytes later
            # and keep going, so coverage is real text coverage instead of
            # "up to the first data blob".
            position = 0
            length = len(code)
            while position < length:
                last = position
                for insn in md.disasm(code[position:], section["addr"] + position):
                    unit_insns += 1
                    last = position + (insn.address - (section["addr"] + position)) + insn.size
                    mnemonic = insn.mnemonic
                    if mnemonic in MTE_MNEMONICS:
                        unit_counts[mnemonic] += 1
                        sites.append(insn.address)
                    elif mnemonic == "dc" and insn.op_str.split(",")[0].strip() == "gzva":
                        unit_counts[GZVA_LABEL] += 1
                        sites.append(insn.address)
                if last == position:
                    position += 4  # undecodable word: skip and resync
                else:
                    position = last
        for key, value in unit_counts.items():
            totals[key] += value
        total_insns += unit_insns
        unit_total = sum(unit_counts.values())

        sym_addrs = [value for value, _ in symbols]
        if symbols and sites:
            for address in sites:
                index = bisect.bisect_right(sym_addrs, address) - 1
                if index >= 0:
                    name = symbols[index][1]
                    all_symbols[name] = all_symbols.get(name, 0) + 1
        if unit_total or unit_insns:
            units.append({"label": label, "insns": unit_insns,
                          "mte": unit_total, "counts": unit_counts})
        if progress:
            print("  scanned %-56s insns=%-9d mte=%d"
                  % (label[:56], unit_insns, unit_total), file=sys.stderr)

    units.sort(key=lambda unit: -unit["mte"])
    return {"totals": totals, "total_insns": total_insns,
            "mte_insns": sum(totals.values()), "units": units,
            "symbols": all_symbols}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary")
    parser.add_argument("--top", type=int, default=15,
                        help="how many kexts/symbols to list (default 15)")
    parser.add_argument("--kext", help="only census kexts whose id contains this")
    parser.add_argument("--csv", metavar="PATH", help="write per-symbol counts")
    parser.add_argument("--section", default="__text")
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args(argv)

    try:
        with open(args.binary, "rb") as handle:
            data = handle.read()
        offset, note, description = unwrap(data)
        slices = read_slices(data, offset)
        result = None
        last_error = None
        for slice_offset in slices:
            try:
                result = census(data, slice_offset, args.section, args.kext,
                                args.progress)
                break
            except ParseError as exc:
                last_error = exc
        if result is None:
            raise ParseError(str(last_error) if last_error else
                             "no arm64 slice found")
    except ParseError as exc:
        print("cannot census %s: %s" % (args.binary, exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print("cannot read %s: %s" % (args.binary, exc), file=sys.stderr)
        return 2

    started = time.time()
    print("file:      %s" % args.binary)
    print("container: %s" % note)
    if description:
        print("build:     %s" % description)
    print("kexts:     %d with code" % len(result["units"]))
    print()
    print("MTE instruction census (section %s)" % args.section)
    print("%-28s %10s" % ("instruction", "count"))
    print("-" * 40)
    for name, value in sorted(result["totals"].items(), key=lambda kv: -kv[1]):
        if not value:
            continue
        print("%-28s %10d  %s" % (name, value, MTE_MNEMONICS.get(name, "")))
    print("-" * 40)
    print("%-28s %10d" % ("MTE total", result["mte_insns"]))
    print("%-28s %10d" % ("instructions", result["total_insns"]))
    if result["total_insns"]:
        print("%-28s %9.3f%%" % ("MTE share",
                                 100.0 * result["mte_insns"] / result["total_insns"]))

    if result["units"]:
        print()
        print("top %d kexts by MTE instructions" % args.top)
        print("%-10s %-10s %-8s %s" % ("mte", "insns", "share", "kext"))
        for unit in result["units"][:args.top]:
            share = (100.0 * unit["mte"] / unit["insns"]) if unit["insns"] else 0.0
            print("%-10d %-10d %7.2f%% %s" % (unit["mte"], unit["insns"], share,
                                              unit["label"]))

    if result["symbols"]:
        print()
        print("top %d symbols by MTE instruction count" % args.top)
        for name, value in sorted(result["symbols"].items(),
                                  key=lambda kv: -kv[1])[:args.top]:
            print("%-8d %s" % (value, name))

    if args.csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["symbol", "mte_instructions"])
            for name, value in sorted(result["symbols"].items(),
                                      key=lambda kv: -kv[1]):
                writer.writerow([name, value])
        print("\nwrote %s" % args.csv)

    print("(%.1fs)" % (time.time() - started))
    print("\ncontribute: open an issue/PR titled 'census: <chip> <build>' and "
          "paste the tables. The numbers are the artifact, not the binary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
