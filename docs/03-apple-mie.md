# 03: Apple MIE (Memory Integrity Enforcement)

Apple's production deployment of EMTE, shipped 2025-09-09 on iPhone 17 family
(A19/A19 Pro) and M5 Macs. Grounded in S1, S2, S3, S4, S5, S6, S7. Related:
[02-emte](02-emte.md), [04-xnu-mte](04-xnu-mte.md), [05-allocators](05-allocators.md), [06-a19-hardware](06-a19-hardware.md).

## Timeline

- 2018: PAC in A12, first in industry. Code flow integrity.
- iOS 15: kalloc_type, kernel secure typed allocator (S21).
- iOS 17: xzone malloc, userland counterpart.
- 2022: EMTE spec (ARMv8.9), Apple co-designed it with ARM.
- 2025-09-09: MIE announced with iPhone 17 / 17 Air / M5.
- 2026: iOS 26.4 flips MTE defaults (pure-data on, third-party soft-mode
  dropped). iOS 27 in beta as of this writing, expansion untracked.

## The three layers

1. Secure typed allocators. Kernel: zalloc hardening + kalloc_type. Userland:
   XZone malloc. These do the heavy lifting and organize memory by type so
   cross-type exploitation is hard (S1, S5, [05-allocators](05-allocators.md)).
2. EMTE in synchronous mode. Used to protect the smaller individual
   allocations inside a type bucket that software allocators cannot defend.
   Apple modeled tag-checking demand and designed silicon to satisfy it (S1).
3. Tag Confidentiality Enforcement (TCE). Protects allocator internals and
   tag values from leaks: PRNG reseeded every context switch
   (PACGA_IRG_RESEED), tag storage behind SPTM (page type XNU_TAG_STORAGE),
   silicon designed so tag values cannot influence speculative execution
   (counter TikTag / StickyTags / Spectre V1) (S1, S5).

## Scope of deployment

- Always on: kernel, plus over 70 userland processes, on all iPhone 17 and
  iPhone Air units. No opt-out for those processes.
- Third-party apps: opt in via Xcode Enhanced Security capability, "Hardware
  Memory Tagging". Entitlement:
  com.apple.security.hardened-process.checked-allocations (S3).
- Soft mode (checked-allocations.soft-mode): simulated crash, non-fatal.
  Intended to validate apps before hard enablement. Forced for third-party
  binaries until 26.4; ignored for platform binaries in lockdown mode (S5).
- Pure data (enable-pure-data): tag data-only allocations. Default on since
  26.4, opt-out via disable-pure-data (S5).

## Entitlements map (S5, S3)

    com.apple.security.hardened-process            MTE enable, platform binaries only
    .checked-allocations                           MTE enable, explicit
    .checked-allocations.soft-mode                 non-fatal faults
    .checked-allocations.{enable,disable}-pure-data  tag data-only allocations
    .checked-allocations.no-tagged-receive         interpreter/JIT opt-out (S3)

## Performance story

- Synchronous always-on with "no noticeable performance impact" claimed (S1).
- Why: allocators first, EMTE only where software cannot defend; silicon
  sized to the modeled demand; A19 dedicated CPU area, speed, and memory for
  tag storage, "more than ever before" (S1).
- ASan comparison: 50-100% slowdown and 2-3x memory vs near-zero and ~3%
  tag storage on A19 (S7 part 1).

## Threat model

- Target: mercenary spyware chains (Pegasus-class). Memory safety bugs are
  the interchangeable backbone of these chains.
- MIE disrupts chains early, when attacker capabilities are still limited,
  making chains fragile and expensive to maintain (S1, S19).
- Effectiveness math: 1/16 per-step tag collision, (1/16)^3 ~ 0.024% for a
  3-step chain (S6).

## Known limits (honest read, S5)

- Intra-object corruption not caught by design.
- Tag leaks remain a research question (Apple claims side-channel
  resistance, no independent public test).
- Non-tagged LARGE/HUGE userland allocations (XZone TODO).
- Powerful primitives like Darksword's LPE remain entry points, they just
  need extra work.
- MTE helps attackers fuzz: find bugs on MTE hardware, reproduce on non-MTE
  devices.
