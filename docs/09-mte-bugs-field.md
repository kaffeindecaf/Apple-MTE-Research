# 09: MTE bugs and crashes in the field

Real crashes and bugs reported publicly on GitHub, across Apple and
Android MTE deployments. This is the field corpus: what MTE actually
catches, what the crash signatures look like, and which classes of code
keep tripping it. Sources are GitHub issues, tagged S25+ in
[links](../resources/links.md). Related: [03-apple-mie](03-apple-mie.md),
[07-attack-surface](07-attack-surface.md), [08-research-methods](08-research-methods.md).

## Apple A19 / MIE crashes

### FuturaeKit on iPhone 17e: EXC_ARM_MTE_TAGCHECK_FAIL (S25)

Open issue, Futurae-Technologies/ios-sdk #64, 2026-06. Third-party auth
SDK crashes at startup on iPhone 17e (iPhone18,5, iOS 26.5.1 23F81),
fine on every older device.

Crash signature:

    Exception Type:    EXC_BAD_ACCESS (SIGKILL)
    Exception Subtype: EXC_ARM_MTE_TAGCHECK_FAIL at 0x0000000d6514c3d8
    Exception Codes:   0x0000000000000106, 0x0000000d6514c3d8
    Termination Reason: Namespace MTE_FAIL, Code 262
    mteState: enabled

Details:

- Fault in a MALLOC_SMALL region (80K rw-/rwx SM=ZER), 984 bytes past
  the previous region boundary. Classic small-heap OOB read.
- Thread 0 (main), in FuturaeKit's own code: `getEnumTagSinglePayload
  for Bag` through a Swift `ClosedRange<>.Index` initializeWithCopy,
  inside an RxSwift-style CompositeDisposable dispose chain on the main
  scheduler.
- So the bug is a UAF or stale-pointer read in the SDK's subscription
  teardown, only exposed by MTE's synchronous checking on A19. The
  vendor confirmed the app "works on all other devices", and the crash
  is deterministic on 17e.
- Takeaway: this is the normal shape of A19 field crashes. Third-party
  code with lifetime bugs that are invisible without tagging, exposed
  only when the app runs on MTE hardware. iPhone 17e is the cheapest
  A19 device, so it shows up in tester fleets first.

### SwiftUI weak-table fault on macOS 27 beta (S27)

Closed issue, cypherair #499 (2026-06), root-caused and filed to Apple
as FB23066215. Not iOS, but the same MTE machinery on arm64e macOS, and
the cleanest public example of an Apple-framework MTE bug.

Signature: EXC_BAD_ACCESS, EXC_ARM_MTE_TAGCHECK_FAIL (MTE_FAIL, code
262), in `weak_clear_no_lock -> clearDeallocating_slow` during
`-[NSTextField dealloc]`, SwiftUI text-field teardown.

Root cause: SwiftUI's `_AppearanceActionModifier.MergedBox` is freed
without deregistering its weak reference to the backing NSTextField
(`.onAppear { focused = ... }` on a bridged field). The stale weak-table
slot faults when the field deallocates. Paired console log:

    objc[...]: Attempted to unregister unknown __weak variable at 0x16...

Notable details:

- Only under hardened-process / MIE v2 entitlements on macOS 27.0
  (26A5353q). Same code crash-free on macOS 26.x / MIE v1.
- `checked-allocations.soft-mode` does NOT downgrade this fault class.
  Soft mode is not a general escape hatch.
- The reporter built a standalone zero-dependency SwiftUI reproducer
  (good practice: excludes the app's own code).
- This is a memory-safety bug in Apple's own framework, caught by
  Apple's own mitigation. MTE as a microscope working as designed.

### ZeroTier fails to launch on macOS 26.1 (S29)

Open issue, zerotier/ZeroTierOne #2540 (2025-11). No window, no process
after install on macOS 26.1. Not yet confirmed as MTE-related (no crash
log posted), but the timing and silence pattern matches the MTE-field-
crash class: processes that crash instantly under tagging produce no
UI and no user-visible error. Worth watching; a crash log would settle
it. Listed here as a candidate, not a confirmed MTE fault.

## Android / Go MTE crashes

### Go runtime trips MTE: indexbyte past granule (S28)

cake-tech/cake_wallet #2921 (2026-02, GrapheneOS Pixel 9): Litecoin
wallet crashes on launch with SEGV_MTESERR inside libmweb.so (Go
bindings). Root-caused by the maintainers to a known Go runtime bug:
golang/go#59090. Go's optimized assembly routines (IndexByte via
`runtime.gostring -> runtime.findnull`) read within a page but past the
16-byte MTE granule boundary, which is a tag violation by definition.

Crash signature:

    signal: 11 (SIGSEGV), code 9 (SEGV_MTESERR), faultAddr 400c01e7c434980
    threadName: let.cake_wallet
    MTE: enabled
    libmweb.so (pc 4d3f38) -- indexbytebody (internal/bytealg/indexbyte_arm64.s)

Takeaways:

- Granule-unaligned word reads are a real MTE tripwire. Code that reads
  a word spanning two granules where the second granule is tagged
  differently faults even though the read is within the allocation
  page. Optimized string/byte routines are the classic offenders.
- Same root cause as facebook/react-native #44276 (libgojni.so MTE crash
  on Pixel 8 Pro, closed 2024): Go shared libraries are a recurring MTE
  crash source on Android. Any vendor shipping Go code into a tagged
  process hits the same assembly.

### GrapheneOS Vanadium MTE crash (S26)

GrapheneOS/Vanadium #1223 (2026-07): Chromium (Vanadium) MTE crash on
Pixel, sync mode. No root cause posted. Included as corpus: even
Chromium with PartitionAlloc MTE support crashes in the field, which is
the expected noise floor for a large C++ codebase under tagging.

### sentry-cocoa: preparing for the entitlement (S30)

getsentry/sentry-cocoa #5412 (2025-06): enable the enhanced security
capability in the iOS-Swift sample app, fix whatever Xcode finds. Notes
the specific risk that swapping `__cxa_throw` for C++ exceptions may
crash under pointer authentication. Useful as a checklist for what a
maintained SDK does before flipping the entitlement: enable, run under
Xcode, fix findings, ship.

## Patterns across the corpus

- Third-party lifetime bugs exposed only on MTE hardware: Futurae,
  godot (S31). The bug existed for years, only the detector is new.
- Framework bugs caught by the vendor's own mitigation: SwiftUI
  weak-table on macOS 27.
- Language-runtime assembly bugs: Go's indexbyte. Granule-unaligned
  reads are the common tripwire, not just heap OOB.
- Crash signatures to grep for in field data: EXC_ARM_MTE_TAGCHECK_FAIL
  (iOS/macOS), Termination Reason MTE_FAIL code 262, SEGV_MTESERR
  (Android), mteState: enabled, "Attempted to unregister unknown __weak
  variable".
- soft-mode does not catch or downgrade everything (S27). Apps that
  validate with soft mode can still hard-crash under the real
  entitlement.

## Open questions

- godot #121736 (S31): iOS 26 XZone type-aware allocator trap in
  `_xzm_xzone_malloc_freelist_outlined` on iPhone 16 Pro (A18, software
  allocator, not hardware MTE). The C#/mono runtime's type-punning
  trips the new allocator. Is the same shape reproducible against
  XZone on A19? See [05-allocators](05-allocators.md).
- How many of the "iPhone 17e / iOS 26 crash, works everywhere else"
  reports in the wild are MTE faults? The Futurae issue is one; the
  class is probably larger. A sysdiagnose/ips corpus would answer it.
- Does the SwiftUI weak-table bug class exist on iOS (UIKit
  equivalents) or only AppKit?

## Adding to this corpus

New entries: keep the signature block (exception type/subtype, codes,
termination reason), the region type, the stack top, and the
root-cause if known. Add the GitHub issue to
[links](../resources/links.md) as S25+. Re-run
`python3 scripts/graph.py` before committing.
