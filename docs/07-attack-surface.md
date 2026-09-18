# 07: Attack surface and bypass research

What MIE does not catch, and where a researcher can productively dig.
Grounded in S5, S1, S6, plus the 2026 exploit record (S35-S37, S52, S54,
S65). Related: [03-apple-mie](03-apple-mie.md), [05-allocators](05-allocators.md),
[08-research-methods](08-research-methods.md).

## What MTE/MIE does not catch

- Intra-object corruption. Overwriting fields inside a live tagged block
  stays within the tag. Apple admits this by design (S5, S1).
- Data-only attacks. The big one since 2026-05 (S35-S37): manipulate
  kernel data structures through logic flaws without corrupting any
  tagged memory. No tag check ever fires because no invalid access ever
  happens. Calif's M5 LPE (CVE-2026-28952) worked exactly this way via
  _zalloc_ro_mut. MIE has no signal to detect this class; it is outside
  the threat model entirely.
- Globals/static in standard MTE. EMTE canonical checking narrows this but
  the tag for untagged memory still matters; the mechanism deserves study.
- Non-tagged size classes: XZone LARGE (32KB-2MB, TODO) and HUGE are not
  enforced (S5).
- The privileged writers. Zones that are read-only to the entire kernel
  are writable through exactly one function, `_zalloc_ro_mut`. MIE
  protects that door with SPTM and then trusts the door's argument
  validation. CVE-2026-28952 was an integer overflow in that validation
  (S54). Anything below the tagging layer is the same story: a physical
  page UAF via a `uint16` refcount wrap reaches freed physical memory
  with every access correctly tagged (S52).
- Tag collisions: 1/16 per access. Probabilistic, not absolute.
- Bugs reached without heap corruption: logic bugs, race conditions in
  non-tagged state, etc.
- Anything after a stronger primitive: kernel R/W via non-heap bugs
  (Darksword LPE class) remains an entry point (S5 closing thoughts).

## P0 findings: MTE-as-implemented gaps (S12, all on Pixel-class MTE)

Project Zero's three-part test series (Mark Brand, pre-production MTE
hardware, 2022-2023) is the reference for what MTE misses in practice.
Bypass classes, from P0's framing:

1. Known-tag bypass: tag values are the whole game. If an attacker can
   learn or forge tags, invalid accesses look valid. Tag confidentiality
   is the mitigation's core assumption.
2. Unknown-tag bypass: implementation limits that let an exploit proceed
   despite detectable wrong-tag accesses.

Hardware-level findings (P0 could NOT find these on their test silicon):

- No additional speculative side channel leaking tag-check
  success/failure beyond ordinary Spectre-class pointer leaks. This is
  the finding Apple's "side-channel resistant" claim builds on, but note
  it was tested on pre-production non-Apple silicon (S12 part 1).
- MTE does not block Spectre: speculative loads with wrong tags still
  leak data (tested with safeside patch). No tag-check-stall on
  speculation.

Async-mode-only weaknesses (why Apple insists on sync):

- Syscall arg accesses unchecked in async mode (kernel skips tag checks
  on user pointers).
- Sync mode converts kernel accesses of bad user pointers to EFAULT,
  which is an oracle: syscalls fail cleanly instead of trapping.
- SIGSEGV is catchable: a corruptible signal handler (Breakpad/Crashpad
  pattern) disables async MTE process-wide. P0 demonstrated a full
  bypass against duktape with this.
- Multi-threaded generic bypass: coerce another thread to do the
  post-fault work before the faulting thread hits a kernel boundary.
- Exploitation window math: with CONFIG_HZ_250 (4ms timer), an
  async-MTE exploit needs ~0.2ms to finish at 95% reliability.

Kernel-specific problems (part 3):

- TCR_ELx.TCMA1: tag 0b1111 pointers bypass checks entirely (needed for
  phys<->virt conversion), so 0xF is a forgeable "trusted" tag in the
  kernel. Apple's answer is SPTM-guarded tag storage, not TCMA1 removal.
- TFSR_EL1 direct access: kernel can clear its own async failure flags.
- DMA and non-MTE coprocessors bypass checks entirely (Apple's SPTM
  protects tag storage but not DMA writes to tagged memory).
- Pointer equality leaks (kcmp, fuse_lock_owner_id, epoll_fdinfo) break
  tag confidentiality in principle.
- TYPESAFE_BY_RCU allocations are exempt by design (legit UAF).

## Speculative tag-leak primitives (S13, S14)

- TikTag (S13): speculative-execution gadgets leak MTE tags from
  arbitrary addresses. 95%+ tag-leak success in <4s, demonstrated
  against Chrome and the Linux kernel, pushes MTE from probabilistic to
  ~100% bypass for the targeted access.
- StickyTags (S14): deterministic round-robin tag assignment by size
  class eliminates retagging overhead (4% vs 20.2% combined
  Scudo+MemTagSanitizer), and shows a contention-based side channel
  reveals whether a tag check mismatches - a probing primitive that
  works without needing to read the tag itself.
- The common primitive: tag-check success/failure is observable via
  microarchitectural effects (speculative leakage or contention),
  so the "guess 1/16" assumption collapses.
- Apple's counter-claims (S5): SoC designed to be resistant to TikTag,
  StickyTags, Spectre-V1 style attacks; PACGA_IRG_RESEED rekeys the tag
  PRNG every context switch; tag storage is SPTM-guarded (XNU_TAG_STORAGE
  page type). Spectre V1 specifically: attacker must chain 25+ V1
  sequences for high exploitability (S51). None of this has been
  independently tested on A19 silicon - that is checklist Tier 4 item 3.

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

11. Trusted-writer argument validation (S54). The small set of kernel
    functions allowed to mutate protected memory is now the highest-value
    surface, and their bounds-check sequences are auditable offline on
    any kernelcache: look for an add feeding a comparison before the
    overflow check on the same add. Sibling candidates listed in
    [10-exploit-examples](10-exploit-examples.md) section 10. No A19
    device needed, which makes this the best offline-first angle on the
    list.
12. Refcount and counter widths below the tagging layer. MIE does not
    watch integer state, and Apple's 26.0-26.4 hardening guarded one
    `uint16` refcount (the `pmap` struct at +0x74, 32 `tbnz` checks)
    while a sibling `pt_desc` refcount kept the same overflow with zero
    guards (S52). Mechanical offline work: enumerate narrow refcount
    fields reachable from the app sandbox and check which ones have
    guards.

## Math to keep in mind

- Per-step tag match: 1/16.
- 3-step chain: (1/16)^3 ~ 0.024% reliable success (S6). This is why MIE
  hurts chains more than single steps.
- MTE catch rate on linear overflows: 15/16 = 93.75% per 8kSec (S7).

## Current public state

- 2026-05: first public kernel exploit surviving MIE (S35-S37). Calif /
  Anthropic Mythos: data-only local LPE on macOS 26.4.1 (25E253),
  CVE-2026-28952, fixed in macOS 26.5. Chain uses two bugs
  (_zalloc_ro_mut overflow + per-CPU allocation bounds), never performs
  memory corruption and never triggers a tag exception, so MIE has
  nothing to intercept. 55-page report withheld until patch adoption.
  This is the data-only attack class: no corruption, no tag fault. The
  instruction-level fix and the sibling-writer hunt list are now
  documented (S54, [10-exploit-examples](10-exploit-examples.md) 10).
- 2026-04 to 2026-09: an independent PoC repo claims the A19 write-through
  result for a physical page UAF reached through a `uint16` `pt_desc`
  refcount overflow (S52). Apple closed it as "expected behavior" and
  flagged the submitted artifacts; the primitive itself sits below the
  tagging layer, which is the part that has to be taken seriously. Reclaim
  is reported blocked on A14+ by SPTM quarantine, so the documented
  outcome is a primitive, not a chain.
- 2026-03: the Coruna exploit kit was leaked and rehosted publicly
  (S57-S59, S66): 5 full chains, 23 exploits, iOS 13.0 - 17.2.1, with a
  working PPL/SPTM bypass via the AGX coprocessor. Pre-MIE devices only,
  but it hands every researcher the blueprint for the layer MIE's tag
  storage rests on. Titan reimplements that bypass (S62).
- Apple: claims speculative resistance, frequent PRNG reseeding,
  SPTM-protected tag storage. No public bypass that actually corrupts
  tagged memory on A19 as of this writing. Apple's advisories never
  mention MIE, so this claim cannot be tracked from release notes (S65).
- Google Pixel MTE: bypassed via TikTag/StickyTags in Chrome and Linux
  kernel (S13, S14). Apple's design explicitly targets those primitives.
- OffensiveCon 2026 (S5): MIE "pretty great but not perfect", Darksword
  LPE still viable entry point, intra-object corruption viable.

## What a 2026-09 A19 researcher should conclude

MIE does its job on the class it was built for: pointer corruption dies at
the access. Every public 2026 chain that survived MIE did so by not
producing a bad access at all - data-only logic flaws (S35-S37), the
trusted writer's own bounds math (S52/S54), or physical-page state below
the tagging layer (S52). The productive questions have therefore moved:

1. Who may write to protected memory, and how is their input validated?
2. Which integer state can be driven from the sandbox without an invalid
   access (refcounts, counters, indices)?
3. Is SPTM itself still the wall it was on A14-A17, now that the tag store
   hangs off it (S60-S62)?

## Ethics note

This file is defense research: understanding limits, building detection and
fuzzing tooling. Any bypass work that emerges should go through responsible
disclosure (Apple Security Bounty) before publication.
