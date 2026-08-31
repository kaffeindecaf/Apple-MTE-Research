# 05: Allocators (kernel + userland)

The allocator layer is where MTE actually lives. Grounded in S5 unless
noted. Related: [03-apple-mie](03-apple-mie.md), [04-xnu-mte](04-xnu-mte.md), [07-attack-surface](07-attack-surface.md).

## Kernel: zalloc

Fixed-size slab allocator, one element size per zone, up to 690 zones,
reached via zone_array[i]. Some zones are compile-time reserved
security-critical (IPC, VM vital structures, thread, proc, cred, sandbox);
the rest are dynamically registered (kalloc, kalloc_type, skmem).

Pre-MTE hardening (S5 slide 33):

    Defense                              Targets
    external bitmap                      no inline metadata to corrupt, double-free detection
    heap separation DATA/PTR/SHARED      cross-type exploitation
    VA sequestering                      cross-zone attacks (VA pinned to zone forever)
    sad feng shui                        predictable heap feng shui
    per-CPU anti-LIFO magazines          freelist manipulation
    zone_require()                       validates zone ownership at runtime
    guard pages (~25% random)            linear overflows between zone chunks
    type segregation (kalloc_type)       type confusion via heap spraying

Attacker view: layout is hard to predict, overflows may face guard pages,
UAF to type confusion is almost impossible, double free is not abusable.
Before MTE the remaining trick was UAF to object confusion within the same
type (memory descriptors, mach ports) (S5 slide 35).

MTE integration: see [04-xnu-mte](04-xnu-mte.md) zalloc section. Key numbers: z_tag bit,
KMA_TAG, 26.4 runtime submap check, even/odd tag spaces, tag-on-free.

## Kernel: kalloc / kalloc_type

kalloc_ext() and kalloc_type(T) serve generic subsystem allocations with
type segregation. They pull from a dedicated zalloc zone or
kmem_alloc_guard with KMA_TAG (S5 slide 28). IOKit's IOMalloc wraps
kheap_alloc -> kalloc_ext.

## Userland: XZone malloc

Replaces ScalableZone on iOS when all of these hold (S5 slide 60):

- boot-arg string has_sec_transition=1 (same flag as kernel MTE)
- hardened-process.hardened-heap entitlement
- process name matches the security_critical hardcoded list
- feature flag SecureAllocator_SystemWide (true on iOS)

When XZone is on, NanoZoneV2 is disabled by default (SecureAllocator_
NanoOnXzone is false on iOS). XZone is a SLAB allocator based on mimalloc
and zalloc design, typed allocations, LIFO ordering. Overview doc in
libmalloc/doc/xzone_malloc.md (S5 slide 62).

Size families (S5 slide 64):

    TINY   16B - 4KB    16KB chunks    lock-free CAS freelist       retag-on-free
    SMALL  4KB - 32KB   64/128KB      bitmap+lock or lock-free     retag-on-realloc
    LARGE  32KB - 2MB   2-128 slices  direct segment / gzone       no tag (yet, TODO)
    HUGE   >2MB         256+ slices   direct VM allocation         no tag

Defenses: separated metadata (some PAC-protected inplace freelist),
separated heaps DATA/PTR, VA sequestering, type segregation, random guard
chunks (security_critical processes only), randomized front index, per-CPU
policy. First N allocations served by MFM, a budget-limited early allocator,
before XZone kicks in (S5 slide 65).

## XZone type segregation

Each allocation routed via _xzm_xzone_lookup(size, type_desc):
size -> bin (size class), type_desc -> bucket (type identity),
xzone index = bin_offset + bucket (S5 slide 66).

- Type descriptors inferred at compile time from struct layout (size, field
  kinds, positioning). Caveat: uintptr_t is treated as DATA (typed i64 by
  LLVM).
- Bucketing keys derived from executable_boothash (boot UUID + cdhash),
  deterministic per boot and per executable (S5 slide 68).
- Buckets: DATA (pure data, no pointers), OBJC (MALLOC_TYPE_KIND_OBJC),
  POINTER 0..3 (4 on macOS, keyed hash of type_desc) (S5 slide 69).

## XZone MTE policy

    Tagging decision per xzone: (TINY OR SMALL) AND (!data OR tag_data)
    VM segments allocated with VM_FLAGS_MTE via mach_vm_map

    Bucket   Tagged by default   Rationale
    PTR      yes                 pointer-bearing, hijackable
    OBJC     yes                 pointer-bearing, hijackable
    DATA     yes (since 26.4)    data is exploitable too (uintptr_t-like, states)

LARGE tagging supported in code but not enforced yet (TODO). Third-party
binaries are no longer forced to soft-mode (since 26.4) (S5 slide 70, 73).

## Userland: libpas (WebKit)

libpas supports MTE but is temporarily forced to soft-mode. Separate
30-min-talk-sized scope (S5 slide 62). JSC/WebKit exploitation angle lives
in [07-attack-surface](07-attack-surface.md) and checklist tier 4.

## Open questions

- Exact XZone bucket hash function and boothash derivation (binary-only).
- MFM early allocator budget and handoff logic.
- Which security_critical process names are on the hardcoded list.
- LARGE tagging enablement timeline across 26.x/27.
