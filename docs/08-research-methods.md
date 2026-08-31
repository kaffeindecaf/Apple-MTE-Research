# 08: Research methods and tooling

How to actually run this research program offline-first, with the local
repos already on disk. Related: [[07-attack-surface]], [[local-tools]],
[[links]].

## MTE as a microscope

The key insight from JAMF (S6): MTE does not just block exploits, it turns
invisible bugs into visible faults. Every iPhone 17 in the field is a
silicon-speed, always-on memory-safety fuzzer on the kernel and 70+
processes.

Worked example (S6): a race-condition UAF deep in the iOS networking stack
panics on iPhone 17 Pro running 26.4. On any non-MTE device the race fires
silently: no crash, no log, no evidence. MIE panics pin the fault to the
exact load/store because checking is synchronous.

New research workflow:

1. Observe the fault: GUARD_EXC_MTE_SYNC_FAULT crash, MTE page tags in the
   log, faulting address (S7 part 2).
2. Root-cause the bug behind the fault (the hard part is done by hardware).
3. Assess impact and exploitability on non-MTE hardware.
4. Report or weaponize accordingly.

## Crash corpus

- W0lfSword has a panic analyzer for NDJSON .ips files. Use it to build a
  corpus of MTE faults once an A19 device is available. [HW]
- 8kSec part 2 documents crash log fields: exception flavor
  GUARD_EXC_MTE_SYNC_FAULT, MTE page tag values (S7 part 2).
- Note: A13/A15 test devices cannot produce MTE faults. Corpus pipeline
  can be built and tested on normal panics, then pointed at MTE data.

## Offline-first strategy (no A19 hardware owned)

- Kernelcaches: fetch the T8150 build via W0lfSword
  scripts/fetch_kernelcache.py (ranged zip64 IPSW fetch) or ipsw.me.
- Offsets: run prebuilt xpf-cli from kernel-deltas tools/ against cached
  kernelcaches. This is exactly how T8150 (iPhone18,1) offsets were already
  verified in W0lfSword offsets.m on 26.0.1/26.1.
- KDK: macOS KDK 26.2 (25C5031i) contains kernel.development.t8142, which
  Jonathan Levin says has "nice MTE insights" (S16). Mirror it.
- Open source: apple-oss-distributions/xnu and libmalloc carry the MTE
  code paths (imgact_setup_sec, zcram_memtag_init, xzone docs) even though
  production binaries diverge. Grep them first, always.
- SPTM firmware: extract sptm.t8150.release from an A19 IPSW for tag
  storage analysis (S5 references it; no public writeup exists).
- Diffs: kernel-deltas kcwatch machinery diffs XPF offset dumps across
  builds. Add T8150 as a watched board to catch MTE struct evolution.

## Environment gaps

- Corellium does not emulate MTE/MIE (S6). Virtualized research cannot
  produce or observe tag faults. Plan around real hardware for anything
  dynamic.
- No public Apple documentation on the 70+ process list, tag PRNG, or tag
  storage internals. Expect to derive these.

## Repos on disk (see [[local-tools]])

- ~/Desktop/kernel-deltas: kcwatch feed, t8030 + t8110 watched, t8103
  defined, T8150 candidate.
- ~/Desktop/W0lfSword: XPF source + CLI, offsets.m, usbtest, panic analyzer.
- ~/Desktop/Apple-Bug-Bounty-Skill: methodology skills, offsets.yaml.

## Reading order for a new session

1. [[graph]] to reorient.
2. [[01-mte-basics]] if MTE theory is cold.
3. [[03-apple-mie]] for the deployment picture.
4. checklist.md tier that is in flight.
5. [[local-tools]] before touching kernelcaches.
