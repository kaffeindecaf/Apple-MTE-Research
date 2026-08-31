# Local tooling integration

How the existing repos on disk plug into this research. Paths are absolute.
Related: [[08-research-methods]], [[links]].

## kernel-deltas (~/Desktop/kernel-deltas)

kcwatch feed repo. Daily GH Actions cron polls ipsw.me for new signed iOS
builds on t8030 (A13) + t8110 (A15), ranged-fetches kernelcaches, resolves
offsets with prebuilt xpf-cli, diffs, commits reports.

For this research:

- Add T8150 (A19) as a watched board. One line in BOARDS dict in
  scripts/kcwatch.py (t8103/A14 already defined as a pattern to copy) plus
  loop entries in .github/workflows/watch.yml. regen auto-discovers boards
  from disk dumps.
- MTE-relevant offsets to add to XPF metric sets (tools/xpf-cli/
  xpf_patched.c), finders permitting:
  task.security_config, task.task_sec_policy, zone.zone_security_flags_t,
  zone submap tagging state. Grep XPF source first: a metric name with no
  registered finder prints 0x0 silently.
- Rebuild xpf-cli via tools/xpf-cli/build.sh inside the W0lfSword checkout
  (XPF/src + ChOma live there), copy binary + xpf_patched.c back.

## W0lfSword (~/Desktop/W0lfSword)

Exploit research toolkit. Relevant pieces:

- kexploit/offsets.m: already carries T8150 (iPhone18,1) XPF-verified
  offsets for 26.0.1 (23A355) and 26.1 (23B85). The comment there labels
  T8150 "A18", conflicting with Wikipedia A19; verify and fix.
- scripts/fetch_kernelcache.py: ranged zip64 IPSW kernelcache fetch. Use to
  pull T8150 kernelcaches for offline XPF runs and MTE instruction census.
- usbtest + panic analyzer (NDJSON .ips): crash pull pipeline for when an
  A19 device is available.
- XPF source: where new MTE offset finders get implemented (XPF/src/
  common.c, non_ppl.c, ppl.c, bad_recovery.c, xpf_item_register).

## Apple-Bug-Bounty-Skill (~/Desktop/Apple-Bug-Bounty-Skill)

- ios-* skills (10 modules) with methodology, bug classes, offset
  migration workflow. The master router and ios-research-methodology apply
  directly to tier 4 goals.
- references/offsets.yaml: canonical offset store. MTE-related offsets
  (task_sec_policy etc.) should land here when discovered, not just in
  offsets.m.
- Contribution loop: novel MTE findings should flow back as skill patches.

## New scripts in this repo

- scripts/graph.py: verifies wikilinks across docs/ and prints the network.
  Run after every doc change.
- Future: crash log parser for GUARD_EXC_MTE_SYNC_FAULT (tier 5),
  XZone bucket RE notes, tag census tooling (tier 4).
