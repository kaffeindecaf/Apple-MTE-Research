# 04: XNU MTE integration

How the kernel activates, configures, and protects MTE. Grounded in S5
(OffensiveCon 2026) unless noted. Related: [[03-apple-mie]], [[05-allocators]],
[[07-attack-surface]].

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
from ScalableZone to XZone malloc (S5, [[05-allocators]]).

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

## Open questions

- Exact SCTLR_EL1 / TFSR_EL1 configuration XNU applies per task.
- Which zones are in the compile-time security-critical set.
- The SPTM tag storage retyping rules in sptm.t8150.release (tier 4).
- TagOffset_EL2 semantics (tier 4).
