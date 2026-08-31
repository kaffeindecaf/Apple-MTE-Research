# Apple MTE Research

Research notes on Apple's Memory Integrity Enforcement (MIE) and the A19
(T8150) silicon generation. Started 2026-08-31. Offline-first: no A19
hardware owned yet, everything below is from public sources and local
kernelcache tooling.

## Docs

| # | Doc | What's in it |
|---|-----|--------------|
| 01 | [mte-basics](docs/01-mte-basics.md) | ARM MTE from the architecture up: granules, tags, instructions, modes. Linux/Android comparison |
| 02 | [emte](docs/02-emte.md) | Enhanced MTE (FEAT_MTE4, Armv8.9): canonical checking, tag permission, FEAT_CPA |
| 03 | [apple-mie](docs/03-apple-mie.md) | How Apple built MIE: the three layers, entitlements, threat model |
| 04 | [xnu-mte](docs/04-xnu-mte.md) | XNU integration: exec-time activation, VM_FLAGS_MTE, zalloc, SPTM tag storage |
| 05 | [allocators](docs/05-allocators.md) | Kernel zalloc + userland XZone malloc, tag policies, zone flags |
| 06 | [a19-hardware](docs/06-a19-hardware.md) | A19/A19 Pro silicon: specs, tag storage layout, A19-exclusive features |
| 07 | [attack-surface](docs/07-attack-surface.md) | What MIE does not catch. P0 findings, TikTag/StickyTags primitives, research angles |
| 08 | [research-methods](docs/08-research-methods.md) | MTE as a microscope, crash mining, offline tooling workflow |
| 09 | [mte-bugs-field](docs/09-mte-bugs-field.md) | Real MTE crashes from the wild (GitHub corpus): signatures, root causes |
| 10 | [exploit-examples](docs/10-exploit-examples.md) | Worked bypass patterns: P0 MTETest, TikTag, StickyTags, TCMA1 0xF |

Plus: [checklist.md](checklist.md) (tiered work queue),
[graph.md](graph.md) (knowledge graph, verified by
[scripts/graph.py](scripts/graph.py)),
[resources/links.md](resources/links.md) (all sources, tagged S1..S50),
[resources/local-tools.md](resources/local-tools.md) (kernel-deltas /
W0lfSword / XPF integration).

## How to navigate

1. New to MTE? Read [01-mte-basics](docs/01-mte-basics.md), then
   [03-apple-mie](docs/03-apple-mie.md).
2. Docs link to each other with relative links, so GitHub renders the
   whole thing as a navigable book. Run `python3 scripts/graph.py` to
   verify nothing dangles (exit 1 on broken links, pre-commit friendly).
3. [checklist.md](checklist.md) is the work queue. Tier 0 and 1 are
   done; tier 4 holds the novel research goals nobody has published.

## Facts locked in (as of 2026-08-31)

- MIE shipped 2025-09-09 with iPhone 17 / 17 Air, and M5 Macs. Built on
  EMTE (FEAT_MTE4, Armv8.9) in synchronous mode only, plus typed
  allocators and tag confidentiality enforcement. Sources: S1, S2.
- A19 = T8150 (iPhone 17 family, board iPhone18,1). M5 = t8142.
  Sources: S17, S5 (sptm.t8150.release / sptm.t8142.release), local
  W0lfSword offsets.m.
- Tag storage is 1/32 of DRAM, at high PA, protected by SPTM as page
  type XNU_TAG_STORAGE. Tag PRNG reseeded every context switch
  (PACGA_IRG_RESEED). Source: S5.
- Kernel + over 70 userland processes are MTE by default. Third-party
  apps opt in via Xcode Enhanced Security capability (hardware memory
  tagging entitlement). Sources: S1, S3.
- iOS 26.4 flipped defaults: DATA allocations tagged, third-party
  soft-mode no longer forced, z_tag became runtime
  zone_submap_has_tagging_enabled. Source: S5.

## Device gap

No A19 hardware owned. Devices on hand: SE2 (A13, no MTE), iPhone 14
(A15, no MTE). Hardware-dependent goals (crash mining on device,
side-channel probing) are marked [HW] in checklist.md and need an
A19/M5 device or a replacement strategy (offline kernelcache analysis,
KDK symbols, SPTM firmware extraction). Research is offline-first.

## Adding docs

New doc: number it, add a one-line entry to the table above, link it
from [graph.md](graph.md) and from neighbors. New source: tag it S##
in [resources/links.md](resources/links.md) and cite it by tag. Run
`python3 scripts/graph.py` before committing.
