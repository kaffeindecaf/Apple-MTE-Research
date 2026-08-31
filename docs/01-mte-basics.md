# 01: ARM MTE basics

What Memory Tagging Extension is, from the architecture up. Grounded in S8,
S10, S11, S20. Related: [02-emte](02-emte.md), [03-apple-mie](03-apple-mie.md).

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
  see [02-emte](02-emte.md).

## Checking modes

- Synchronous: fault raised immediately at the faulting access. Precise
  faulting address, best for security, highest cost. Apple uses this only.
- Asynchronous: fault deferred to next context synchronization point. Lower
  cost, race window for the attacker. Apple explicitly refuses this (S1).
- Asymmetric (ARMv8.7): sync on reads, async on writes. GrapheneOS uses
  this in userland; Android recommends it over pure async (S11).

Linux fault delivery (S10): sync -> SIGSEGV with si_code=SEGV_MTESERR and
precise faulting address (access not performed); async -> SIGSEGV with
SEGV_MTEAERR and si_addr=0 (faulting address unknown). If SIGSEGV is
ignored/blocked in sync mode the process dies with a coredump.

## OS integration (Linux as reference)

Full Linux userland model, per kernel docs (S10):

- Hardware advertised via HWCAP2_MTE (AT_HWCAP2 auxv).
- mmap/mprotect flag PROT_MTE (0x20): pages allow access to allocation
  tags. Only works on MAP_ANONYMOUS and RAM-backed files (tmpfs, memfd);
  anything else returns -EINVAL. Cannot be cleared by mprotect. Tags set
  to 0 on first map, preserved on CoW. MADV_DONTNEED / MADV_FREE may clear
  tags at any point.
- prctl PR_SET_TAGGED_ADDR_CTRL (55): PR_TAGGED_ADDR_ENABLE, mode bits
  PR_MTE_TCF_NONE / SYNC / ASYNC, tag mask PR_MTE_TAG_MASK (0xfffe = all
  15 non-zero tags). Multiple modes allowed; kernel picks per-CPU
  preferred mode (sysfs cpu<N>/mte_tcf_preferred, default async) else
  preference order async > asymmetric > sync.
- PSTATE.TCO disables checking per thread (MSR TCO, #1). Signal handlers
  always run with PSTATE.TCO=0; restored on sigreturn.
- No match-all logical tag exists for userspace. Kernel accesses to user
  memory: unchecked in NONE/ASYNC, best-effort in SYNC, always effective
  TCO=0.
- execve resets everything: PR_TAGGED_ADDR_ENABLE=0, no modes, tag mask 0,
  PSTATE.TCO=0, no PROT_MTE mappings. fork() inherits config + maps.
- Debug: PTRACE_PEEKMTETAGS / PTRACE_POKEMTETAGS (4-bit tag per byte in
  iovec), plus NT_ARM_TAGGED_ADDR_CTRL regset. Core dumps carry tags in
  PT_AARCH64_MEMTAG_MTE segments (p_filesz = p_memsz/32; a 4K page = 128
  bytes of tags).

Android specifics (S11): MTE is opt-in per process. Build-time
sanitize:{memtag_heap:true} (async) or +diag (sync); runtime overrides via
system property arm64.memtag.process.<basename> or env MEMTAG_OPTIONS;
apps via android:memtagMode=(off|default|sync|async) manifest attribute or
NATIVE_MEMTAG_[A]SYNC compat change. Allocator tuning: mallopt
M_MEMTAG_TUNING_BUFFER_OVERFLOW (deterministic adjacent tags, catches
linear overflow, ~half tag space for UAF) vs M_MEMTAG_TUNING_UAF (random
tags, ~93% UAF detection). Kernel: CONFIG_KASAN_HW_TAGS (MTE-accelerated
KASAN), kasan.mode=[sync|async], kasan.fault=[report|panic] (tag checking
disabled after first report).

Apple replaces this whole model with entitlements and VM_FLAGS_MTE, see
[03-apple-mie](03-apple-mie.md) and [04-xnu-mte](04-xnu-mte.md).

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
