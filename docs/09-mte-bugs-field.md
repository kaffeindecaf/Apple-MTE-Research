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

### M5 driver host killed by an MTE tag check: eqvol (S53)

Open issue, Jocala/eqvol #1, filed 2026-09-18. Apple M5 Max, macOS 26.7
(25G229), eqVol 1.1 with eqvol.driver 1.3.1. The driver host process
(`com.apple.audio.Core-Audio-Driver-Service.helper`) is killed about
15 ms after coreaudiod loads the driver, so the device never registers.
Deterministic, 7/7 attempts, identical stack. Install is fine: signed,
notarized, `spctl` accepts it.

Crash signature:

    termination: MTE_FAIL (code 262)
    exception:   EXC_BAD_ACCESS (SIGKILL)
    subtype:     EXC_ARM_MTE_TAGCHECK_FAIL at 0x0e00000c42c1c6e0
    mteState:    enabled

Faulting thread, top frames:

    0  eqvol.driver  one-time initialization function for properties
    1  libdispatch   _dispatch_client_callout
    2  libdispatch   _dispatch_once_callout
    3  eqvol.driver  EQVDeviceCustom.properties.unsafeMutableAddressor
    4  eqvol.driver  EQVDevice.hasProperty(objectID:address:)
    5  eqvol.driver  EQV_HasProperty(...)
    6  (Apple)       -[Core_Audio_Driver has_property:reply:]

Why this one is worth keeping: the reporter did the triage properly. The
tag byte differs run to run (0x04 / 0x08 / 0x0a / 0x0c / 0x0e) while the
untagged address 0xc42c1c6e0 lands inside a live `MALLOC_SMALL` region,
which points at a real use-after-free or overrun into an adjacent
allocation rather than a null or wild pointer. `mteState: enabled` says
the driver host runs under MIE on macOS 26, and the loaded plug-in
inherits checking: on pre-M5 Macs the same access would likely go
unnoticed. Same shape as Futurae (S25) - third-party code, real lifetime
bug, only visible once tagging is on, and now on macOS driver-host code
rather than an iOS SDK.

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

## The other side: CVE-2026-28952, data-only LPE surviving MIE (S35-S37)

2026-05, macOS 26.4.1 (25E253) on M5 with kernel MIE enabled. Calif +
Anthropic Mythos. First public kernel exploit that works with MIE
fully on: a local unprivileged user runs normal syscalls and gets a
root shell. Two bugs (an overflow in `_zalloc_ro_mut` and per-CPU
allocation bounds), no memory corruption performed, no tag exception
ever triggered. Fixed in macOS 26.5 (2026-05-11); 55-page technical
report withheld until patch adoption is wide.

Why it belongs in the corpus: it is the counter-example to every crash
above. The Futurae/Godot/SwiftUI crashes are MTE doing its job -
detecting real corruption. CVE-2026-28952 is the class MTE cannot see:
logic flaws that never produce an invalid access. Full analysis in
[10-exploit-examples](10-exploit-examples.md) section 8 and
[07-attack-surface](07-attack-surface.md).

## MTE crash-reporting toolchain: build timeline (S55, S56)

Where the field-crash machinery actually lives, from binary diffs rather
than from Apple documentation.

iOS 26.0 beta 9 (23A5336a) -> 26.0 RC (23A340), ReportCrash and
CoreDiagnostics gain the whole MTE crash pipeline (S55):

    isMTECrash, observedMTECrashWithProcessName:
    mtePageTags, formatMTEPageTags:report:
    "MTE Page Tags (faulting address: %p)"
    "MTE Malloc Size Class: "
    "Unable to determine malloc size class for empty MTE tags"
    "Unable to determine malloc size class for uniform MTE tags"
    GUARD_EXC_MTE_SYNC_FAULT, GUARD_EXC_MTE_ASYNC_USER_FAULT
    kGUARD_EXC_MTE_ASYNC_KERN_FAULT
    EXC_ARM_MTE_TAGCHECK_FAIL, "Error querying if MTE is enabled"
    "MTE_FAIL", "isFreed", "blamedAllocation", "libsystem_sanitizers.dylib"

Read: on iOS the "MTE Page Tags" block in a .ips, the malloc size class
line and the freed-allocation blame are RC-era additions, so a crash
report from an earlier 26.0 beta may lack them. Worth knowing before
comparing reports across builds.

One unresolved item: the cross-major diff 26.5 (23F77) .vs 27.0 beta 1
(24A5355q) lists `formatMTEPageTags:report:` and `mtePageTags` as absent
from the 27.0 beta CoreDiagnostics symbol list. Follow-up done: the
same-major 27.0 beta 1 -> beta 2 -> beta 3 CoreDiagnostics diffs also do
not mention them, so it is not a one-build artifact. The MTE exception
codes still exist in the 27.0 SDK headers (`EXC_ARM_MTE_TAGCHECK_FAIL`,
`EXC_ARM_MTE_CANONICAL_FAIL`), so this reads as a relocation or rename
inside the reporting stack rather than a removal of MTE crash
classification. Which binary formats the page-tag block in iOS 27 is
still open (needs a 27.x dyld/shared-cache look).

Exception codes for crash triage (S56): the iOS 26.4 and 27.0 SDK
`mach/arm/exception.h` both define

    EXC_ARM_MTE_TAGCHECK_FAIL    0x106   MTE tag check failure
    EXC_ARM_MTE_CANONICAL_FAIL   0x107   MTE canonical tag access fail

0x107 is the canonical-check failure (EMTE-specific), distinct from the
plain tag mismatch. Both numbers appear in crash logs as `Exception
Codes` (0x106 paired with the faulting address is the usual field shape,
see Futurae above).

## Apple advisories do not track MIE (S65)

None of the 2026 advisory pages checked (macOS Tahoe 26.5, iOS 26.6,
26.6.1, 26.7, iOS 27) mentions "Memory Integrity", "memory tagging",
MTE or tagged memory anywhere. Kernel entries arrive as generic prose:
"unexpected system termination or corrupt kernel memory", "an app may be
able to gain root privileges". Consequences for this KB:

- You cannot track MIE-relevant fixes from release notes. Only binary
  diffing (S55, kernel-deltas) can answer "did the tag path change".
- A CVE description cannot tell you whether MTE caught the bug.
- Kernel-section CVE volume per release, counted from the iOS advisory
  pages: 26.6 (2026-07-27) 23 of 97; 26.6.1 (2026-08-17) 4 of 35;
  26.7 (2026-09-14) 18 of 82; iOS 27 (2026-09-14) 20 of 126. Memory-safety
  kernel bugs did not stop arriving after MIE shipped, which is the
  expected result: MIE changes exploitability, not discovery.
- May 2026 window (macOS Tahoe 26.5) is the one credit set worth naming:
  CVE-2026-28952 (Calif.io + Claude/Anthropic Research) and
  CVE-2026-28951 (Csaba Fitzl) both Kernel, plus CVE-2026-28972 (OOB
  write, STAR Labs). See [10-exploit-examples](10-exploit-examples.md)
  section 10.

## Patterns across the corpus

- Third-party lifetime bugs exposed only on MTE hardware: Futurae,
  godot (S31). The bug existed for years, only the detector is new.
- The same class now shows up on macOS in kernel-adjacent code: driver
  host processes carry MIE, and a plug-in they load inherits tag
  checking, so a third-party audio driver dies 15 ms after load (S53).
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
- Where did the MTE page-tag formatter go in iOS 27.0 (CoreDiagnostics
  diff, S55)? Narrowed: it is absent from the CoreDiagnostics symbol
  diffs across 27.0 beta 1-3, while the MTE exception codes remain in the
  27.0 SDK, so the symbol moved or was renamed rather than the feature
  being dropped. Finding the new home needs a 27.x userland look.
- Which kernel CVEs in the 26.7 / iOS 27 kernels were caught by MTE and
  which are pre-existing silent corruption? The advisories do not say
  (S65); answering it needs kernelcache diffs plus tagging-aware triage.

## Adding to this corpus

New entries: keep the signature block (exception type/subtype, codes,
termination reason), the region type, the stack top, and the
root-cause if known. Add the GitHub issue to
[links](../resources/links.md) as S25+. Re-run
`python3 scripts/graph.py` before committing.
