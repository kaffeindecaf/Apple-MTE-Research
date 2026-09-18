# Research checklist

Goals for the Apple MTE / A19 research program. Tier 0 is done. Tier 4 is the
novel work: things with little or no public coverage. Items marked [HW] need
an A19 or M5 device.

## Tier 0: base research bootstrap (done 2026-08-31)

- [x] Create repo skeleton: README, graph, checklist, docs/, resources/, scripts/
- [x] Core source sweep: Apple MIE blog (S1), PSG (S2), Xcode docs (S3),
      OffensiveCon 2026 slides (S5), JAMF (S6), 8kSec parts 1-2 (S7)
- [x] Local copy of OffensiveCon 2026 PDF in resources/papers/ (now
      gitignored; kept as agent-private reference)
- [x] A19 spec pass: Wikipedia (S17), NotebookCheck (S18)
- [x] Identify T8150 = A19 in existing W0lfSword offsets.m data
- [x] graph.py wikilink verifier

## Tier 1: MTE / EMTE theory mastery (done 2026-08-31)

- [x] Read ARM MTE intro doc (S8) end to end, annotate [01-mte-basics](docs/01-mte-basics.md)
- [x] Read ARM EMTE / Armv8.9 feature doc (S9): list every MTE4 feature and
      what Apple uses. Annotated [02-emte](docs/02-emte.md): canonical checking, tag
      permission, store-only, enhanced fault reporting; Apple uses
      canonical + sync only
- [x] Read Project Zero "MTE as Implemented" parts 1-3 (S12), extract
      implementation-level gaps relevant to Apple. See [07-attack-surface](docs/07-attack-surface.md)
      (known/unknown-tag bypass classes, async weaknesses, TCMA1 0xF tag)
- [x] Read TikTag (S13) and StickyTags (S14) papers, write up the exact
      speculative primitives Apple claims to be resistant to. See
      [07-attack-surface](docs/07-attack-surface.md): tag-check observability via speculative
      leakage + contention probing
- [x] Understand FEAT_CPA (checked pointer arithmetic, ARMv9.5): what it
      would add on top of EMTE, whether A19 has it (check kernelcache hw
      feature registers). CPA = overflow-checked pointer arithmetic,
      optional Armv9.4 / mandatory Armv9.5, ID_AA64ISAR3_EL1.CPA.
      A19 presence: needs T8150 kernelcache check (tier 5 tooling) [HW]
- [x] Compare Linux MTE (S10) and AOSP MTE (S11) vs Apple: prctl/entitlement
      model, PROT_MTE vs VM_FLAGS_MTE, sync vs async vs asymmetric.
      Annotated [01-mte-basics](docs/01-mte-basics.md)

## Tier 2: A19 hardware mapping

- [ ] Build full A19/A19 Pro spec table with sources (caches, clocks, RAM,
      GPU, NE, ISA) and flag discrepancies (ARMv9.4-A vs v9.2-A claims)
- [ ] Map the MIE silicon investment: tag storage (1/32 DRAM), TagOffset_EL2,
      PHYS_SLIDE layout. Only fragments public (S5 slide 18, S16)
- [ ] Investigate Apple10 GPU: neural accelerators in GPU cores, what they
      mean for GPU memory tagging and GPU-side exploitation
- [ ] Track A19-exclusive non-MTE features: Wi-Fi 7 chip, ProRes RAW, ISP,
      display engine, LPDDR5X-9600, vapor chamber. Keep a running list
- [ ] [HW] Check MTE-related CPUID/hw feature bits on an A19 device
      (hw.optional.arm.*, SCTLR_EL1 config after boot)

## Tier 3: XNU internals

- [ ] Reverse imgact_setup_sec() decision tree from the T8150 kernelcache:
      inheritance, posix_spawn flags, hardened-process entitlement, AMFI
      opt-out (S5 slide 19). Confirm on 26.x and 27 beta
      (offline half done 2026-09-18: the task_has_sec_soft_mode / _inherit
      / _never_check and checked-allocations strings are present in A19
      kernelcaches and absent in A13, so the paths are compiled in for A19.
      Function-level RE is blocked on symbols, tier 10)
- [ ] Map task->security_config and task_sec_policy layout and task_has_sec_*()
      helpers, feed offsets into W0lfSword offsets.m / XPF
- [ ] Decode VM_FLAGS_MTE plumbing: PTE tag bit, CoW restrictions, tag strip
      on inheritance and OOL mach messages (S5 slide 24)
- [ ] Reverse zalloc MTE paths: zone_security_flags_t z_tag, 26.4
      zone_submap_has_tagging_enabled, zcram_memtag_init tag pattern
      (even/odd tag spaces), tag-on-free policy
- [ ] Diff 26.0 vs 26.4 vs 26.x kernelcaches on MTE code paths (use
      kernel-deltas machinery, add T8150 board first)
- [ ] Identify the KHEAP_ID_DATA_PRIVATE / DATA_SHARED split call sites
- [ ] Understand SPTM tag storage handling: XNU_TAG_STORAGE page type in
      sptm.t8150.release, TagOffset_EL2, retyping rules (S5, S15, S16)
- [ ] Decode crash log format: GUARD_EXC_MTE_SYNC_FAULT, exception flavors,
      MTE page tag fields (S7 part 2). Build a parser for .ips panic files

## Tier 4: novel research (things nobody has really seen)

- [ ] Extract and RE sptm.t8150.release firmware from an A19 IPSW. Focus on
      the tag storage page type and tag storage VA mapping. SPTM firmware RE
      is referenced (S5) but no public writeup of the tag storage paths exists
- [ ] Tag PRNG analysis: PACGA_IRG_RESEED behavior, tag distribution across
      allocations and context switches. Nobody has published statistics on
      Apple tag generation. Feasible offline via allocator source + logic
- [ ] Speculative side-channel probing of Apple MTE (TikTag-style). Apple
      claims resistance; no independent public test on A19 silicon exists.
      [HW]
- [ ] XZone malloc closed-source RE: the libmalloc open source covers docs
      but the production XZone implementation is binary-only. RE the
      _xzm_xzone_lookup path, bucketing keys (executable_boothash), MFM
      early allocator budget
- [x] MTE instruction census of the T8150 kernelcache: count and locate
      STG/LDG/IRG sites, map which subsystems actually use tags.
      Done 2026-09-18 (S67): 884 sites in 26.6.1, 713 in 27.0, 882/711 of
      them in com.apple.kernel __TEXT_EXEC, 2 in Libm, none elsewhere; A13
      and A12 kernels have 0. Subsystem mapping needs symbols, tier 10.
      See [11-t8150-kernelcache](docs/11-t8150-kernelcache.md)
- [ ] Identify the 70+ userland processes with MTE by default: strings /
      entitlement scan across dyld shared cache, crash log telemetry. No
      public list exists
- [ ] libpas (WebKit) soft-mode analysis: what happens when JSC hits a tag
      fault in soft mode, exploitation implications for WebContent
- [ ] Intra-object corruption paths: field-level overwrite within a tagged
      block, combine with tag leak to build a working strategy (S5 closing
      thoughts)
- [ ] OOL mach message tag stripping: can tags be laundered through IPC to
      build a fake-tag primitive?
- [ ] Lockdown Mode x MTE interaction: soft-mode ignored for platform
      binaries in lockdown (S5). Test what lockdown actually changes
- [ ] iOS 27 MIE expansion tracking: does MIE reach more processes, does
      Lockdown Mode broaden MTE, any A19-only 27 features. Track betas
      (2026-09-18: kernel-side first data point in tier 10, MTE sites fell
      884 -> 713 from 26.6.1 to 27.0 while tag strings grew; userland side
      still open)
- [ ] A19 vs M5 MTE parity: t8142 kernelcache and macOS KDK 26.2 has "nice
      MTE insights" (S16). Compare kernel MTE config between iOS and macOS

## Tier 5: tooling

- [ ] Add T8150 (A19) board to kernel-deltas kcwatch.py BOARDS dict and
      watch.yml. First A19 offset-delta feed
- [ ] Add MTE-related offsets to XPF metric sets (task.security_config,
      task.task_sec_policy, zone.zone_security_flags_t, zone.submap tagging)
- [ ] Wire XPF offline runs against cached T8150 kernelcaches; commit dumps
      as evidence in kernel-deltas style
- [ ] Build the crash log corpus: pull .ips from test devices (A13/A15 have
      no MTE, so focus on parsing pipeline readiness for A19)
- [ ] KDK acquisition: grab macOS KDK 26.2 (kernel.development.t8142) for
      symbolicated MTE code, mirror to resources/
      (now the top blocker: the shipped A19 kernelcache is stripped, see
      tier 10)

## Tier 6: writeups

- [ ] Publishable writeup: "MTE in XNU on A19" (allocator + VM + SPTM)
- [ ] Publishable writeup: A19-exclusive features from a researcher POV
- [ ] Any tier 4 finding that lands -> write it up, offer to PR into
      Apple-Bug-Bounty-Skill or W0lfSword tooling

## Tier 7: field corpus (done 2026-08-31)

- [x] GitHub sweep for A19 / MIE / MTE crashes and bugs, document in
      [09-mte-bugs-field](docs/09-mte-bugs-field.md) (S25..S34)
- [x] Document real crash signatures: EXC_ARM_MTE_TAGCHECK_FAIL,
      MTE_FAIL code 262, SEGV_MTESERR, weak-table faults
- [x] Exploit examples doc [10-exploit-examples](docs/10-exploit-examples.md): P0 MTETest patterns,
      TikTag, StickyTags, TCMA1 0xF, EFAULT oracle
- [x] Convert repo to relative markdown links so GitHub renders the
      knowledge graph (graph.py now checks md links too)

## Tier 8: 2026 source sweep (done 2026-08-31)

- [x] Sweep for 2026 MTE/MIE developments, add S35..S50 to
      [links](resources/links.md)
- [x] CVE-2026-28952: first public kernel exploit surviving MIE
      (data-only LPE, _zalloc_ro_mut, fixed macOS 26.5). Documented in
      [07-attack-surface](docs/07-attack-surface.md) + [10-exploit-examples](docs/10-exploit-examples.md)
- [x] XZone open source: libmalloc-792 doc + memento introspection
      (S42-S44) folded into [05-allocators](docs/05-allocators.md)
- [x] A19 die shots / floorplan data (S39-S41) folded into
      [06-a19-hardware](docs/06-a19-hardware.md)
- [x] Hands-on MIE experiments (S38), allocator MTE survey (S45),
      Folded-Tag/IUBIK/NanoTag papers (S46-S48), MTE perf study (S49)
      added to links
- [x] .gitignore for agent-private reference material
      (resources/papers/, downloads, kernelcaches, scratch)

## Tier 9: 2026-09 GitHub exploit/CVE sweep (done 2026-09-18)

- [x] GitHub sweep for MTE/MIE exploits: repos, code, issues. Found the
      pmap_tte_remove physical-UAF PoC repo (S52), the eqvol M5 field
      crash filed the same day (S53), the Coruna kit ecosystem
      (S57-S62), an RISC-V MIE model (S63) and a republished XNU typed
      allocator (S64)
- [x] New CVEs documented with attribution: CVE-2026-28952 (instruction
      level, S54), CVE-2026-28951 / -28972 (same release window), kernel
      CVE counts for iOS 26.6 / 26.6.1 / 26.7 / iOS 27 (S65)
- [x] MTE crash-reporting build timeline from ipsw-diffs symbol diffs:
      pipeline appears in 26.0 RC; MTE exception codes 0x106/0x107 in the
      26.4 and 27.0 SDK headers (S55, S56)
- [x] Confirmed Apple's advisories never mention MIE, so release notes
      cannot be used to track MIE-relevant fixes (S65)
- [x] Docs updated: [10-exploit-examples](docs/10-exploit-examples.md)
      sections 9-11 (physical UAF, trusted writer, PPL/SPTM layer),
      [09-mte-bugs-field](docs/09-mte-bugs-field.md) (eqvol, reporting
      timeline, advisory gap), [07-attack-surface](docs/07-attack-surface.md)
      (new angles + current state), [04-xnu-mte](docs/04-xnu-mte.md)
      (trusted writer, exception codes)
- [ ] Offline: disassemble `_zalloc_ro_mut` and the sibling RO writers in
      a cached macOS 26.5+ kernel.development.t8142 and check every
      bounds-check sequence for the same check-order pattern (S54)
- [ ] Offline: enumerate narrow (uint8/uint16) refcount fields in pmap /
      VM / IPC structures and check which ones lack overflow guards (S52)
- [ ] Resolve the per-CPU RO subzone fields (TPIDR_EL1 + 0x158 / + 0xe8)
      against a T8150 kernelcache
- [ ] Settle the iOS 27.0 CoreDiagnostics question: same-major
      beta-to-beta diff for formatMTEPageTags:report: (S55)
- [ ] Reimplement the crash-report classifier against the symbol set in
      S55 (isMTECrash / GUARD_EXC_MTE_* / MTE_FAIL 262 / isFreed) so
      `.ips` triage matches what ReportCrash actually emits
- [x] Contribution tooling: [mte_device_report.py](../scripts/mte_device_report.py)
      (device identity + MTE verdict + crash/syslog collection),
      [mte_crash_scan.py](../scripts/mte_crash_scan.py) (corpus-style MTE
      triage of .ips/.panic, local or pulled),
      [mte_insn_census.py](../scripts/mte_insn_census.py) (per-kext MTE
      instruction census, fileset-aware). `scripts/tests/test_contrib_tools.py`
      covers all three. README asks for device data (see Want to help?)
- [x] Collect census numbers: done offline from the IPSW (S67), A13 t8030
      26.6.1 = 0 MTE sites in its kernel, T8150 26.6.1 = 884, T8150 27.0 =
      713. No contributor hardware needed
- [ ] First device report from an A19 or M5 device (the tool writes it, no
      jailbreak needed)
- [x] Settle the iOS 27.0 CoreDiagnostics question: absent from the
      CoreDiagnostics symbol diffs across 27.0 beta 1-3 while the MTE
      exception codes remain in the 27.0 SDK, so it moved or was renamed.
      Finding the new home needs a 27.x userland look (S55)

## Tier 10: A19 kernelcache, offline RE (started 2026-09-18)

The shipped T8150 kernelcache is fetchable without a device (S67) but
stripped, so this tier splits into what the stripped file gives us and what
needs symbols.

- [x] Fetch + unwrap pipeline: fetch_kernelcache.py ranged zip64 read,
      pyimg4 im4p extract (auto-detects LZFSE), 22.0 MB -> 72.7 MB Mach-O
      for 26.6.1 and 23.4 MB -> 78.1 MB for 27.0, 298/301 fileset kexts
- [x] MTE instruction census, both builds, versus A12/A13 controls
- [x] String inventory A19 26.6.1 vs A19 27.0 vs A13 (task_has_sec_*,
      checked-allocations, tag_storage, mte_, SPTM counts)
- [x] Confirm the RO-writer family exists in the shipped A19 kernel
      (_zalloc_ro_mut, _zalloc_ro_mut_atomic and neighbours in the name
      table at 0x44d3e8x, plus the "Invalid atomic operation" panic string)
- [x] Tooling: [kc_strings.py](../scripts/kc_strings.py) (strings / xref /
      diff) with its own tests, and the census resync fix that took
      coverage from 71% to 100% of text words
- [ ] Get symbols: development kernel or KDK (tier 5) unlocks every item
      below
- [ ] Attribute the 884 / 711 MTE sites to functions: how many are zalloc
      paths (vm_memtag_load_tag / store_tag / zcram_memtag_init) versus VM
      tag plumbing
- [ ] Find who computes the tag value (1 IRG total; STG-family sites take a
      register operand)
- [ ] Diff 26.0 / 26.4 / 26.5 / 26.6.1 / 27.0 to see whether the 884 -> 713
      move is a step or a trend
- [ ] sptm.t8150.release extraction: does the tag-write path live there
      (tier 4 item, same fetch machinery can grab the im4p)
- [ ] M5 t8142 census for iOS/macOS parity
