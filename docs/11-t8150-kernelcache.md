# 11: A19 (T8150) kernelcache, offline

First offline look at a shipped A19 kernel. Grounded in S67 (the IPSW
kernelcache) unless noted. Related: [04-xnu-mte](04-xnu-mte.md),
[05-allocators](05-allocators.md), [07-attack-surface](07-attack-surface.md),
[08-research-methods](08-research-methods.md).

## The artifact

    device      iPhone18,1 (iPhone 17 Pro)
    iOS         26.6.1, build 23G83
    zip entry   kernelcache.release.v53   (new naming: not .iphoneXX)
    payload     IM4P, LZFSE-compressed, 22,035,992 bytes
    extracted   72,712,192 bytes, raw Mach-O (feedfacf)
    im4p desc   KernelManagement_host-487.100.11
    layout      298 fileset kexts, 301 __text sections, 46.2 MB of text

    sha256 (im4p) 451d8c1c07011f523a92702147e30173466e4121c64fa4c853c765053d2b8a33
    sha256 (kc)   24916b87bb82d33df69ddc9cfe408cd090b792d79693d395101fb42771972565

iOS 27.0 (24A437) fetched the same way: `kernelcache.release.v53`,
23,390,465-byte payload, 78,135,296-byte Mach-O, 301 kexts.

    sha256 (im4p) bbbe3dae59116ca636220fa0e46124f9d7b22c61b591b1233950eeb5de5f0b1c
    sha256 (kc)   81280162c11eec579d4cfb377a96a5f9cdf4396eed2a7f0213e5072e1e5e0e0f

Fetch (no device needed, ~30 s, few hundred MB of range reads):

    python3 ~/Desktop/W0lfSword/scripts/fetch_kernelcache.py <ipsw-url> t8150.img4
    pyimg4 im4p extract -i t8150.img4 -o t8150.kc --lzfse
    python3 scripts/mte_insn_census.py t8150.kc --top 20

The kernelcache itself stays local: `resources/kernelcaches/` is gitignored.
What follows is the numbers, which is what a PR can carry.

## MTE instruction census

Same tool, same section (`__text`, all segments), three builds:

    kernelcache            kexts  instructions   MTE insns   where
    t8150 (A19) 26.6.1       298      11,543,576         884   com.apple.kernel 882, Libm 2
    t8150 (A19) 27.0         301      12,391,587         713   com.apple.kernel 711, Libm 2
    t8030 (A13) 26.6.1       235       9,834,496           2   Libm 2, kernel 0
    t8110 (A12) 26.6.1       248      10,027,269           2   Libm 2, kernel 0

Per-mnemonic split, A19 26.6.1 -> 27.0:

    ldg    788 -> 619   load allocation tag
    st2g    26 ->  26   store allocation tag, two granules
    gmi     26 ->  26   tag mask insert into a pointer
    stgm    23 ->  22   store allocation tags, range
    stg     16 ->  16   store allocation tag
    ldgm     4 ->   3   load allocation tags, range
    irg      1 ->   1   insert random tag

Everything sits in `com.apple.kernel / __TEXT_EXEC` (882 sites = 0.039% of
that kext's 2,264,040 instructions in 26.6.1, 711 in 27.0) plus 2 sites in
`com.apple.kec.Libm`, and nothing in any other kext. The A12/A13 kernels
contain zero MTE instructions outside Libm, whose 2 `st2g` are a compiler
pattern, not tag code.

What this does and does not say, kept separate on purpose:

- Measured: on A19 the tag-aware code paths exist in kernel text; on A13/A12
  they do not. That is the offline confirmation of the KB's kernel-MTE claim
  (S1, S5 could not be checked against a shipped A19 kernel before this).
- Measured: the sites are almost all LDG (reading allocation tags) with a
  small set of tag stores and exactly one IRG, and 26.6.1 -> 27.0 lost 171
  sites (ldg -169) while gaining 3 kexts and 850k instructions. Site counts
  are static, not execution frequency, so this says the code shape changed,
  not that tagging got weaker.
- Hypothesis, not fact: tag *generation* for the kernel heap probably does not
  happen in kernel text (one IRG in 11.5M instructions). A tag store
  (STG/ST2G/STGM) takes its value from a register, so whoever computes it is
  the interesting party: either the allocator reads it from elsewhere, or SPTM
  owns it (XNU_TAG_STORAGE is an SPTM page type, S16/S51). Settling this needs
  symbolication, see below.
- Method warning worth remembering: capstone's `disasm()` stops at the first
  word it cannot decode, and `__text` contains literal pools and padding. The
  first version of the census reported 0 MTE instructions on both kernels for
  exactly that reason. `mte_insn_census.py` now resyncs 4 bytes and keeps
  going, which took A19 coverage from 8.2M to 11.54M instructions (100% of
  text words). Any "0 hits" result from a linear sweep should be treated as
  suspect until coverage is checked.

## Symbols: the shipped kernelcache is stripped

All 298 kexts carry `LC_SYMTAB` with `nsyms = 0` and `strsize = 1`. There is
no symbol table to resolve: `imgact_setup_sec`, `_zalloc_ro_mut`,
`task_has_sec_*`, `zone_submap_has_tagging_enabled` cannot be located by name
in this artifact. This is the hard blocker for the tier 3 items that need
function identity, and the reason tier 5 wants a development kernel
(`kernel.development.*` from a KDK, or a symbolicated t8142).

What is still available without symbols:

- the string/name table (zone and kalloc_type names, panic format strings)
- string cross-references, via `scripts/kc_strings.py xref`

## String inventory: A19 26.6.1 vs A19 27.0 vs A13

Counts of the literal string in each kernelcache (same tool, three builds):

    string                     t8150 26.6.1  t8150 27.0  t8030 26.6.1
    task_has_sec_soft_mode                1            1            0
    task_has_sec_inherit                  1            1            0
    task_has_sec_never_check              1            1            0
    checked-allocations                   5            5            0
    hardened-process                     16           18           11
    tag_storage                          11           26            0
    mte_                                 10           19            0
    SPTM                                 17           22            2
    kalloc_type                         306          309          245
    _zalloc_ro_mut                        3            3            3
    XNU_TAG_STORAGE                       0            0            0
    vm_memtag                             0            0            0
    zone_security_flags                   0            0            0

Reading:

- the sec-policy names (`task_has_sec_soft_mode`, `_inherit`,
  `_never_check`) and the `checked-allocations` entitlement string are present
  in A19 builds and absent in A13, which matches S5's `imgact_setup_sec`
  decision tree on real A19 code
- 26.6.1 -> 27.0 grew the tag-related strings (tag_storage 11 -> 26, mte_
  10 -> 19, SPTM 17 -> 22) while the MTE instruction site count fell: more of
  the tag handling is expressed in data and tables in 27.0, less inline. That
  is a direction of travel, not a measured behaviour change
- absence of `XNU_TAG_STORAGE`, `vm_memtag_load_tag` or
  `zone_security_flags` as strings means nothing: those are identifiers the
  compiler drops, not log format strings

## The RO-writer family (tier 9 item)

`_zalloc_ro_mut` and friends do appear in the A19 kernel as a name run
(file offset 0x44d3e8x, alphabetical):

    _zalloc_flags, _zalloc_noblock, _zalloc_ro_clear, _zalloc_ro_mut,
    _zalloc_ro_mut_atomic, _zdestroy, _zfree, _zfree_ro, _zinit,
    _zone_create, _zone_create_ro ...

with the panic string `Invalid atomic operation: %d @%s:%d` and
`zalloc_internal.h` next to it. So the trusted-writer family named in
[10-exploit-examples](10-exploit-examples.md) section 10 is present in the
shipped A19 kernel, but as data, not as addressable symbols. Cross-referencing
those strings came up empty (`xref` covers adrp+add and table-loaded
pointers; name tables consumed by index will not show up), so
`_zalloc_ro_mut`'s code address in this build has to come from symbolication.

## Tooling added for this

    scripts/kc_strings.py strings <file> [PATTERN]   string inventory, with VM
                                                     address and section
    scripts/kc_strings.py xref <file> <SUBSTRING>    code that materialises a
                                                     string address
    scripts/kc_strings.py diff <a> <b>               string set difference
    scripts/mte_insn_census.py <file> --top N --csv  per-kext MTE census

Coverage limits stated plainly: `xref` handles direct address formation and
pointer-table loads (chained-fixup offsets included); string references built
as base+index inside a table, and ObjC/CFString metadata paths, are not
covered and report as "no references found".

## Open questions

- which function holds the 882 (26.6.1) / 711 (27.0) A19 MTE sites, and how
  many belong to zalloc versus the VM tag plumbing (needs symbolication)
- what computes the tag value: 1 IRG in 11.5M instructions is too few for
  per-allocation tag generation in kernel text
- why did ldg sites drop by 169 between 26.6.1 and 27.0 while tag strings grew
- does `sptm.t8150.release` carry the tag-write paths instead (tier 4)
- M5 (`t8142`) parity: same census on a macOS kernel, expected to differ
- 26.0 / 26.4 / 26.5 builds: is the 884 -> 713 move gradual or a 27.0 step

## Reproducing all of the above

    # fetch + unwrap (no device, ~30 s each)
    python3 ~/Desktop/W0lfSword/scripts/fetch_kernelcache.py <ipsw-url> kc.img4
    pyimg4 im4p extract -i kc.img4 -o kc            # auto-detects LZFSE

    # numbers in this doc
    python3 scripts/mte_insn_census.py kc --top 12
    python3 scripts/kc_strings.py strings kc task_has_sec
    python3 scripts/kc_strings.py diff a.kc b.kc --min 8

    # tests for both tools
    python3 scripts/tests/test_contrib_tools.py
    python3 scripts/tests/test_kc_strings.py
