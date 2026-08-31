# 06: A19 / A19 Pro hardware

The first Apple silicon with MTE. Grounded in S17, S18, S5. Related:
[03-apple-mie](03-apple-mie.md), [07-attack-surface](07-attack-surface.md).

## Identity

    A19         codename Tilos,  part number T8150
    A19 Pro     codename Thera,  part number T8150 (per S17; unconfirmed split)
    Process     TSMC N3P (3nm enhanced)
    ISA         ARMv9.4-A per S17, ARMv9.2-A per LowEndMac. Flagged, verify.
    Announced   2025-09-09, launched 2025-09-19
    Devices     A19: iPhone 17, iPhone 17e, Studio Display
                A19 Pro: iPhone 17 Pro, iPhone 17 Pro Max, iPhone Air,
                Studio Display XDR

Board IDs: iPhone18,1 = iPhone 17 (T8150, confirmed by local XPF runs in
W0lfSword offsets.m on 26.0.1/26.1), iPhone18,2 = iPhone 17 Pro (V54AP).
M5 = t8142 (S5 references sptm.t8142.release, S16 uses kernel.development.
t8142). The W0lfSword offsets.m comment labels T8150 "A18", which conflicts
with S17; treat as a labeling error to fix in that repo.

## CPU and caches

    Core config   2P + 4E
    P clock       4.26 GHz
    E clock       2.26 GHz (A19), 2.6 GHz (A19 Pro, per S18)
    L1I           192KB P / 128KB E
    L1D           128KB P / 64KB E
    L2            A19 8MB P / 4MB E; A19 Pro 16MB P / 6MB E
    L3 / SLC      A19 12MB; A19 Pro 32MB
    SLC is the main differentiator between A19 and A19 Pro (S18)

## Memory

    A19      8GB LPDDR5X-8533, 64-bit 4ch, ~68.2 GB/s
    A19 Pro  12GB LPDDR5X-9600, 64-bit 4ch, ~76.8 GB/s (Air: 8533)

## GPU (Apple10 architecture)

- A19: 4-core (17e) / 5-core (17). 80 EUs, 640 ALUs, 5 clusters.
- A19 Pro: 5-core (Air) / 6-core (Pro, Pro Max). 96 EUs, 768 ALUs,
  6 clusters, up to 1620 MHz.
- Doubled FP16 vs previous gen.
- Neural accelerators (tensor cores) integrated into each GPU core, for
  matrix multiply. Up to ~4x peak GPU compute vs A18 Pro.
- Ray tracing, updated dynamic caching, unified image compression.

## Neural engine

16 cores, 35 TOPS. Same silicon as A17/A18; A19 Pro is faster thanks to
memory bandwidth and the GPU neural accelerators.

## A19-exclusive features (researcher standpoint)

- MIE: first and only mobile Apple silicon with EMTE. Dedicated CPU area,
  CPU speed, and memory for tag storage, "more than ever before" (S1).
  Tag storage = 1/32 of DRAM. See [03-apple-mie](03-apple-mie.md), [04-xnu-mte](04-xnu-mte.md).
- Side-channel-resistant MTE design (TikTag/StickyTags/Spectre V1 counter
  claims, unverified publicly).
- GPU tensor cores (Apple10) and what they mean for GPU memory tagging and
  GPU-side exploit surface.
- Apple-designed Wi-Fi 7 chip in iPhone 17.
- A19 Pro: ProRes RAW exclusively, updated ISP + display engine.
- LPDDR5X-9600, vapor chamber cooling in Pro models.

## Die / floorplan data (S39, S40, S41)

- A19 Pro die ~98.6 mm2 on TSMC N3P, ~10% smaller than A18 Pro (105
  mm2). A19 roughly 9% smaller than A18. Transistor count estimated
  25-30 billion (S39, S40).
- Cache macro roughly doubled (S40 forum data, unconfirmed): P-core L2
  shared 16MB on A19 Pro.
- TechInsights floorplan analysis of the TMUA28 die exists but is
  paywalled (S41).
- Nobody has yet annotated the die area used for MTE tag storage /
  tag RAM. The tag storage is 1/32 of DRAM (S5) but its silicon
  footprint is unmeasured. ChipWise / TechInsights images are the raw
  material for that analysis.

## What is NOT A19-exclusive

- MIE on M5 Macs (same EMTE sync deployment).
- xzone malloc (iOS 17+), kalloc_type (iOS 15+): software, available
  broadly.
- PAC, SPTM, TXM: older silicon.

## Open questions

- Actual die area for tag storage / tag RAM. Nobody has published a die
  analysis. Corellium and others do not emulate MTE (S6).
- Whether A19 implements FEAT_CPA or other ARMv9.5 features.
- A19 vs M5 MTE parity (checklist tier 4, macOS KDK 26.2 has MTE symbols
  per S16).
