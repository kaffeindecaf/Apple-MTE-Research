# Apple MTE Research

Research knowledge base for Apple's Memory Integrity Enforcement (MIE) and the
A19 (T8150) silicon generation. Started 2026-08-31. Local only, nothing pushed
to origin yet.

## What this repo is

A navigable network of documents and resources (a minimal knowledge graph) for
researching:

1. How ARM MTE and Enhanced MTE (EMTE) work at the architectural level
2. How Apple built MIE on top of EMTE, across silicon, XNU, and userland
3. What is exclusive to A19/A19 Pro hardware, from a security researcher standpoint
4. Research angles nobody has published on yet (see checklist.md tier 4)

The graph is [[graph]]: every document links to its neighbors with wikilinks,
and scripts/graph.py verifies and prints the network so nothing dangles.

## Layout

    README.md          this file
    checklist.md       research goals, tiered, with checkboxes
    graph.md           the knowledge graph: nodes + edges
    docs/              the documents (nodes)
      01-mte-basics    ARM MTE fundamentals: granules, tags, modes
      02-emte          Enhanced MTE (MTE4): canonical checking, CPA
      03-apple-mie     Apple MIE: layers, deployment, threat model
      04-xnu-mte       XNU integration: exec time activation, VM, SPTM tag storage
      05-allocators    kernel zalloc + userland XZone malloc MTE policies
      06-a19-hardware  A19/A19 Pro silicon: specs + A19-exclusive features
      07-attack-surface  what MIE does not catch, research angles
      08-research-methods  MTE as microscope, crash mining, offline tooling
    resources/
      links.md         external sources, tagged S1..S24
      local-tools.md   kernel-deltas / W0lfSword / XPF integration
      papers/          offlinecon-2026-navigating-mte-landscape.pdf (local copy)
    scripts/
      graph.py         wikilink scanner + network printer

## How to navigate

1. Read [[graph]] for the map.
2. Read [[01-mte-basics]] first if MTE is new, then [[03-apple-mie]].
3. Use the wikilinks: every doc links to related docs, so you can hop.
4. Run `python3 scripts/graph.py` to list all nodes, edges, and dangling links.
5. checklist.md is the work queue. Tier 4 holds the novel research goals.

## Facts locked in (as of 2026-08-31)

- MIE shipped 2025-09-09 with iPhone 17 / 17 Air, and M5 Macs. Built on EMTE
  (FEAT_MTE4, ARMv8.9) in synchronous mode only, plus typed allocators and tag
  confidentiality enforcement. Source: S1, S2.
- A19 = T8150 (iPhone 17 family, board iPhone18,1). M5 = t8142. Sources: S17,
  S5 (sptm.t8150.release / sptm.t8142.release), local W0lfSword offsets.m.
- Tag storage is 1/32 of DRAM, at high PA, protected by SPTM as page type
  XNU_TAG_STORAGE. Tag PRNG reseeded every context switch (PACGA_IRG_RESEED).
  Source: S5.
- Kernel + over 70 userland processes are MTE by default. Third-party apps opt
  in via Xcode Enhanced Security capability (hardware memory tagging
  entitlement). Source: S1, S3.
- iOS 26.4 flipped defaults: DATA allocations tagged, third-party soft-mode
  no longer forced, z_tag became runtime zone_submap_has_tagging_enabled.
  Source: S5.

## Device gap (important)

No A19 hardware is owned. Devices on hand: SE2 (A13, no MTE), iPhone 14 (A15,
no MTE). Hardware-dependent goals (crash mining on device, side-channel
probing) are marked in checklist.md and require an A19/M5 device or a
replacement strategy (offline kernelcache analysis, KDK symbols, SPTM firmware
extraction). Research is offline-first for now.
