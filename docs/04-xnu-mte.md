# 04: XNU MTE integration

How the kernel activates, configures, and protects MTE. Grounded in S5
(OffensiveCon 2026) unless noted; the trusted-writer and exception-code
sections come from S54 and S56. Related: [03-apple-mie](03-apple-mie.md), [05-allocators](05-allocators.md),
[07-attack-surface](07-attack-surface.md).

## Physical memory layout (tag storage)

    Low PA                    PHYS_SLIDE region            High PA
    +-----------------+--------------------------------+-----------------+
    | firmwares       | AVAILABLE                      | TAG STORAGE     |
    | SEP TXM SPTM KC | covered by XNU vm_pages        | 1/32 of DRAM    |
    +-----------------+--------------------------------+-----------------+
                                                    ^
                                                    TagOffset_EL2

- Tag storage sits at high physical addresses, one 4-bit tag per 16-byte
  granule, 1/32 of DRAM (S5 slide 18).
- TagOffset_EL2: the EL2 register/mechanism locating tag storage. Public
  detail is thin; the layout is a research target (checklist tier 2/4).
- SPTM owns tag storage as a dedicated page type, XNU_TAG_STORAGE. Page
  retyping rules for tag storage pages are part of SPTM's state machine
  (S5, S16). Tag storage stays protected even with a compromised kernel
  (S7 part 1).

## Activation: per-process, at exec time

Decision tree in XNU imgact_setup_sec() (S5 slide 19):

1. MTE inheritance enabled? -> inherit and mirror parent state.
2. posix_spawn explicit enable? -> enable via spawn flags.
3. hardened-process entitlement (or platform && DriverKit)? -> enable via
   entitlements.
4. AMFI opt-out present? -> disable.
5. Otherwise disable.

When MTE activates, XNU:

- sets task->security_config.sec to true
- sets task->task_sec_policy to represent the MTE configuration
- injects has_sec_transition=1 as an Apple boot-arg string
- later checks use task_has_sec_*() helpers

There are boot-args and posix_spawn flags equivalent to the entitlements
(S5 slide 20). has_sec_transition=1 is also the gate that switches userland
from ScalableZone to XZone malloc (S5, [05-allocators](05-allocators.md)).

## VM layer, userland

- MTE-capable task may pass VM_FLAGS_MTE when mapping memory. Enforced at
  every level of the VM structures; the PTE itself flags the page as
  taggable.
- Tagged mappings restrict CoW and cross-process sharing to prevent tag
  leakage:
  - no CoW for tagged memory
  - inheritance or OOL mach messages force a copy, tags stripped
- The codebase is still evolving (S5 slide 24).

## VM layer, kernel

    Layer   API                          Tagged allocation role
    VM      vm_page_grab*()              physical pages, VM_PAGE_GRAB_MTE
    VM      vm_page_alloc_list()         batch, KMA_TAG
    kmem    kmem_alloc*()                huge wired, KMA_TAG, size > 32KB

VM_PAGE_GRAB_MTE / KMA_TAG are only used through exclaves_memory_alloc,
kalloc_large, and the Zalloc APIs (S5 slide 26). kalloc APIs allocate from
either a dedicated zalloc zone or kmem_alloc_guard with KMA_TAG.

## zalloc MTE policy

- Tagging on via the z_tag bit in zone_security_flags_t, default 1 except
  for RO and DATA zones. Forces zone init/expand through KMA_TAG with tagged
  blocks (S5 slide 36).
- Since 26.4: z_tag replaced by runtime zone_submap_has_tagging_enabled().
  RO submap still never tagged; DATA can now be tagged.
- 26.4: KHEAP_ID_DATA_BUFFERS split into KHEAP_ID_DATA_PRIVATE (tagged) and
  KHEAP_ID_DATA_SHARED (not tagged) (S5 slide 37).
- Tag-on-free policy across the full element lifecycle: blocks come pre-
  tagged on allocation; tags initialized when a fresh page is grabbed
  (zcram_memtag_init, mte_generate_and_store_tag with zone_mte_exclusion_mask).

## Tag pattern detail (26.4+)

zcram_memtag_init tags a fresh zone page with an alternating pattern based
on block position:

- even block positions: tag space {2, 4, 6, 8, A, C, E}
- odd block positions: tag space {1, 3, 5, 7, 9, B, D}
- dead space between/around elements: tagged 0

On allocation, vm_memtag_load_tag() loads the stored tag into the returned
pointer. On free, the block is retagged (tag-on-free), so a stale pointer
hits a different tag on next use (S5 slides 39-45).

## Tag confidentiality enforcement (kernel side)

- Tag PRNG reseeded at every context switch, PACGA_IRG_RESEED macro (S5).
- SoC designed to be side-channel resistant against TikTag, StickyTags,
  Spectre V1 (S1, S5).
- Spectre V1 detail (S51): Apple's mitigation forces an attacker to
  chain 25+ V1 sequences for a high exploitability rate. Concrete
  number, useful for modeling attack cost on A19.
- Kernel accesses on behalf of an app are subject to the same
  tag-checking rules as userspace (S2).

## SPTM / TXM context (S51, S15, S16)

The monitor layer MIE sits on, for the generation table:

    Feature          A11-A14, M1      A15+, M2+          A19, M5
    page tables      PPL              SPTM               SPTM
    code signing     ppl.c            txm.c              txm.c
    tag storage      -                -                  SPTM (XNU_TAG_STORAGE)

- ppl.c and txm.c implement the same API (register_code_signature,
  verify_code_signature, associate_jit_region, toggle_developer_mode,
  enter_lockdown_mode); enforcement moves to a different monitor per
  generation (S51).
- Kernel R/W still reaches everything typed XNU_DEFAULT (most of kernel
  heap), but not: page tables, read-only zones (credentials, MACF
  labels), TXM trust-cache slabs, SPTM frame table, Secure Kernel
  domain (S51).
- SPTM endpoints: XNU calls endpoint #1, TXM #3, SK via SVC/HVC gated
  through VBAR_GL2. Darwin 24 had 34 XNU endpoints (0-33); Darwin 25
  adds 37-42 (S16, S51).
- MTE tag storage only appears in A19 IPSWs (iPhone18,4 and higher);
  SPTM defines XNU_TAG_STORAGE as its own page type in the retyping
  state machine (S16).

## The trusted writer: _zalloc_ro_mut

Read-only zones (credentials, task control blocks, MACF labels, signing
state) are unwritable even for kernel code. `_zalloc_ro_mut` is the one
function that may briefly make an RO page writable, write, and seal it
again, with SPTM refusing every other page-table change. MIE therefore
rests on that function's argument validation, and CVE-2026-28952 is
exactly that: an unchecked `target + len` in its stack-area filter, where
a wrapping `len` sent control straight to the writer, spilling bytes into
the adjacent RO slot (S54, detail and the 26.5 fix in
[10-exploit-examples](10-exploit-examples.md) section 10).

Consequences worth carrying:

- RO-zone mutation is an audit target, not a black box. The caller
  supplies the `target` pointer, and the arithmetic between caller and
  destination is attacker-influenced if the caller is reachable.
- The 26.5 fix moved the overflow check ahead of the comparison and added
  a per-CPU RO subzone bound (`TPIDR_EL1 + 0x158` / `+0xe8`). Those two
  per-CPU fields are new offsets worth resolving against the T8150
  kernelcache when it is available.
- Sibling writers with the same shape: `_zalloc_ro_mut_atomic`, zone
  resize paths, signing-flag mutators, sandbox-slot updaters.

## Crash classification codes

SDK headers (S56) define the two MTE exception codes XNU reports:

    EXC_ARM_MTE_TAGCHECK_FAIL    0x106   MTE tag check failure
    EXC_ARM_MTE_CANONICAL_FAIL   0x107   MTE canonical tag access fail

0x106 is the plain tag mismatch; 0x107 is the canonical-check failure that
only exists with EMTE canonical checking. Both appear in `.ips` reports as
`Exception Codes` alongside the faulting address. The userland reporting
path (isMTECrash, formatMTEPageTags, mtePageTags, GUARD_EXC_MTE_*_FAULT)
landed in 26.0 RC - see [09-mte-bugs-field](09-mte-bugs-field.md).

## Open questions

- Exact SCTLR_EL1 / TFSR_EL1 configuration XNU applies per task.
- Which zones are in the compile-time security-critical set.
- The SPTM tag storage retyping rules in sptm.t8150.release (tier 4).
- TagOffset_EL2 semantics (tier 4).
