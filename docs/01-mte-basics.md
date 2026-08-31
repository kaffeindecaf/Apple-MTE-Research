# 01: ARM MTE basics

What Memory Tagging Extension is, from the architecture up. Grounded in S8,
S10, S11, S20. Related: [[02-emte]], [[03-apple-mie]].

## The idea

Every memory allocation gets a 4-bit tag. Pointers that reference the
allocation carry the same tag in spare address bits. On every load and store
the CPU compares pointer tag against memory tag. Mismatch = tag check fault.
No software overhead for the check itself, it happens in silicon.

## Mechanics

- Granule: 16 bytes. One 4-bit allocation tag per granule.
- Tag storage: implementation-defined physical storage, roughly 3% of DRAM
  (Apple: 1/32, S5). Normal loads and stores cannot touch it.
- Pointer tag: bits [59:56] of the virtual address, made available by TBI
  (Top Byte Ignore). The MMU ignores the top byte for translation, so the
  tag rides free.
- Tag value: 4 bits = 16 values. 0xF is the canonical (non-tagged) tag in
  standard MTE usage. OffensiveCon counts 15 usable values (S5).
- Statistical detection: an attacker guessing a tag succeeds with p = 1/16
  per access. A 3-step exploit chain drops to (1/16)^3 ~ 0.024% (S6).

## Instructions

    IRG    generate random tag into pointer (uses PRNG)
    ADDG/SUBG  add/sub tag offset to pointer, with granule alignment
    GMI    get tag from memory, insert into pointer
    LDG/STG    load/store allocation tag of address
    STZG   store zero tag
    LDGM/STGM  load/store multiple tags
    ST2G/STZ2G double-granule variants

## Tagging scopes

- Heap: allocator assigns random tag per allocation, retags on free/realloc.
  Catches OOB (adjacent allocations have different tags) and UAF (freed
  block retagged before reuse).
- Stack: compiler aligns objects to 16 bytes and tags them (aarch64
  -mtag-stack or similar). Sequential over/underflows hit neighboring tags.
- Globals/static: NOT tagged by standard MTE. This is the hole EMTE closes,
  see [[02-emte]].

## Checking modes

- Synchronous: fault raised immediately at the faulting access. Precise
  faulting address, best for security, highest cost. Apple uses this only.
- Asynchronous: fault deferred to next context synchronization point. Lower
  cost, race window for the attacker. Apple explicitly refuses this (S1).
- Asymmetric (ARMv8.7): sync on reads, async on writes. GrapheneOS uses
  this in userland; Android recommends it over pure async.

## OS integration (Linux as reference)

- prctl PR_SET_TAGGED_ADDR_CTRL with PR_TAGGED_ADDR_ENABLE, mode bits, tag
  mask. PROT_MTE on mmap for tagged mappings.
- execve resets everything: tagging off, no modes, tag mask 0, PSTATE.TCO=0.
- Android: memtag_heap sanitizer flag, async by default, sync via
  SANITIZE diag. Kernel MTE on Pixel with async.
- Apple replaces this whole model with entitlements and VM_FLAGS_MTE, see
  [[03-apple-mie]] and [[04-xnu-mte]].

## Fault behavior

Tag check fault reports as a synchronous exception (data abort with a
specific syndrome). On Apple it surfaces as GUARD_EXC_MTE_SYNC_FAULT in
crash logs with MTE page tag fields (S7 part 2). On Linux it is SIGSEGV with
SEGV_MTEAERR / SEGV_MTESERR si_code.

## Key references

- S8: ARM intro to MTE
- S10: Linux kernel MTE doc (prctl details, modes)
- S11: AOSP MTE doc (async/asymmetric guidance)
- S20: HackTricks (instruction list, granule math)
- S12: Project Zero MTE as implemented (implementation gaps, 2023)
