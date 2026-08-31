# 07: Attack surface and bypass research

What MIE does not catch, and where a researcher can productively dig.
Grounded in S5, S1, S6. Related: [[03-apple-mie]], [[05-allocators]],
[[08-research-methods]].

## What MTE/MIE does not catch

- Intra-object corruption. Overwriting fields inside a live tagged block
  stays within the tag. Apple admits this by design (S5, S1).
- Globals/static in standard MTE. EMTE canonical checking narrows this but
  the tag for untagged memory still matters; the mechanism deserves study.
- Non-tagged size classes: XZone LARGE (32KB-2MB, TODO) and HUGE are not
  enforced (S5).
- Tag collisions: 1/16 per access. Probabilistic, not absolute.
- Bugs reached without heap corruption: logic bugs, race conditions in
  non-tagged state, etc.
- Anything after a stronger primitive: kernel R/W via non-heap bugs
  (Darksword LPE class) remains an entry point (S5 closing thoughts).

## Research angles (ranked by novelty)

1. Tag leakage. Apple claims speculative-execution resistance (TikTag,
   StickyTags, Spectre V1). No independent public test on A19 silicon
   exists. Offline first steps: understand exactly which microarchitectural
   paths TikTag used, then design the A19 equivalent. [HW]
2. Tag PRNG analysis. PACGA_IRG_RESEED at every context switch. Questions:
   seeding entropy source, tag distribution, prediction window between
   reseeds, correlation across processes. Nobody has published Apple tag
   generation statistics. Partially offline (allocator source + kernelcache).
3. Intra-object corruption + tag leak combo. If you can leak the tag of a
   neighbor block, an intra-object overwrite can extend into it. S5
   explicitly flags intra-object corruption "can help leak tags".
4. OOL mach message tag stripping. Inheritance and OOL messages force
   copies with tags stripped (S5 slide 24). Can tags be laundered through
   IPC to forge pointers in another process?
5. Soft-mode abuse. Third-party binaries were forced to soft-mode until
   26.4. Any residual soft-mode processes are crash-only, no termination:
   a free crash oracle for an attacker. Check current status on 26.4+ and
   27. Also lockdown mode ignores soft-mode for platform binaries (S5):
   what flips?
6. Entitlement confusion. MTE enablement is entitlement-driven
   (imgact_setup_sec). Can a sandboxed process inherit MTE state or spawn
   children with MTE disabled? posix_spawn flags path is a lever (S5
   slide 19).
7. Fuzzing asymmetry. MTE devices surface bugs that are invisible on
   non-MTE hardware. A bug found on an MTE device can often be reproduced
   and exploited on non-MTE devices, which still exist in bulk (S5, S6).
   The JAMF case (race UAF in networking stack, panic only on iPhone 17
   Pro 26.4) shows the signal value (S6).
8. WebKit / libpas. libpas supports MTE but is forced to soft-mode (S5).
   JSC exploitation surface: does WebContent get tags, what does a soft
   fault look like, can it be weaponized as an oracle?
9. CoW and shared memory restrictions. Tagged mappings forbid CoW and
   strip tags on sharing (S5). Shared memory is a prime tag-leak and
   tag-forge surface across processes.
10. Allocator metadata. XZone separates metadata but some inplace freelists
    are PAC-protected (S5). The bitmap/metadata structures are a target if
    you can reach them via a partial overwrite.

## Math to keep in mind

- Per-step tag match: 1/16.
- 3-step chain: (1/16)^3 ~ 0.024% reliable success (S6). This is why MIE
  hurts chains more than single steps.
- MTE catch rate on linear overflows: 15/16 = 93.75% per 8kSec (S7).

## Current public state

- Apple: no known public bypass of MIE on A19. Claims speculative
  resistance, frequent PRNG reseeding, SPTM-protected tag storage.
- Google Pixel MTE: bypassed via TikTag/StickyTags in Chrome and Linux
  kernel (S1). Apple's design explicitly targets those primitives.
- OffensiveCon 2026 (S5): MIE "pretty great but not perfect", Darksword
  LPE still viable entry point, intra-object corruption viable.

## Ethics note

This file is defense research: understanding limits, building detection and
fuzzing tooling. Any bypass work that emerges should go through responsible
disclosure (Apple Security Bounty) before publication.
