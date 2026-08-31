# 02: Enhanced MTE (EMTE / FEAT_MTE4)

The ARMv8.9 (2022) extension set Apple co-designed with ARM. Apple calls the
result EMTE and builds MIE on it. Grounded in S1, S5, S6, S9, S22. Related:
[[01-mte-basics]], [[03-apple-mie]].

## Why standard MTE was not enough

Apple evaluated MTE as a real-time defensive measure and found weaknesses
"unacceptable" for their goals (S1). Two headline problems:

1. Non-tagged memory (globals, static, BSS) was not checked. Attackers could
   pivot through OOB bugs in tagged heap to directly modify untagged state.
2. Async mode leaves a race window. Apple: "We would not implement such a
   mechanism. Memory safety protections need to be strictly synchronous, on
   by default, and working continuously" (S1, S19).

## What EMTE adds (MTE4 feature set)

- Canonical tag checking: accessing untagged memory from a tagged pointer
  now requires knowing the tag. Closes the globals/BSS hole. This is the
  feature Apple calls out by name (S1).
- Store-only tag checking: an additional mode where only store operations
  are checked, for performance-sensitive contexts (S6, S22).
- Enhanced fault reporting: all non-address bits reported on a tag check
  fault, giving the kernel more diagnostic info (S6).
- Tag permission: STG/LDG can be denied through untagged PTEs (S5).
- Related ARMv9.5 work: FEAT_CPA (checked pointer arithmetic), which makes
  pointer arithmetic itself checked. Not part of MTE4 but adjacent; open
  question whether Apple silicon implements it (checklist tier 1).

## Apple's read on EMTE

- EMTE = MTE4, a bundle of four MTE extensions (S22 podcast discussion).
- Apple required synchronous checking only (S6: "EMTE requires synchronous
  checking (immediate exceptions)").
- 8kSec frames the result as three pillars: type-aware allocators, EMTE with
  synchronous faults, SPTM hypervisor protection of tag storage even with a
  compromised kernel (S7 part 1).
- Apple claims MIE is the "first ever comprehensive, always-on memory safety
  protection" covering kernel + 70+ userland processes (S1).

## Specs

- S9: ARM Armv8.9 architecture extension doc (the MTE4 features)
- S5: OffensiveCon summary of the MTE4 feature list
- S22: securitycryptographywhatever podcast walking through what EMTE adds

## Open questions

- Does A19 implement FEAT_CPA? Check hw.optional.arm.* on device [HW].
- Which MTE4 sub-features does XNU actually enable via SCTLR_EL1 / TFSR?
  Offline answerable from the T8150 kernelcache setup code.
