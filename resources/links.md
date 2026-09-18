# External sources

Tagged S1..S67, cited from docs/. Local copies in resources/papers/ are
gitignored (agent-private reference material, not repo content); the
links below are the source of truth.

## Apple primary

- S1: Apple Security Research blog, Memory Integrity Enforcement: A complete
  vision for memory safety in Apple devices (2025-09-09)
  https://security.apple.com/blog/memory-integrity-enforcement/
- S2: Apple Platform Security Guide, Operating system integrity (MIE
  section, A19 and M5+)
  https://support.apple.com/en-lamr/guide/security/sec8b776536b/1
- S3: Xcode docs, Enabling enhanced security for your app (entitlements,
  soft mode, pure data)
  https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app
- S4: Meet with Apple video, Secure your app with Memory Integrity
  Enforcement (Julian, developer security tools team)
  https://developer.apple.com/videos/play/meet-with-apple/206/
- S21: Apple Security Research blog, Towards the next generation of XNU
  memory safety: kalloc_type
  https://security.apple.com/blog/towards-the-next-generation-of-xnu-memory-safety/

## Deep technical analysis

- S5: OffensiveCon 2026, Navigating the MTE Landscape (FuzzingLabs, Atlan
  Pinabel and Patrick Ventuzelo). Local copy:
  resources/papers/offensivecon-2026-navigating-mte-landscape.pdf
  https://fuzzinglabs.com/wp-content/uploads/2026/05/Navigating_iOS_MTE_Landscape.pdf
- S6: JAMF Threat Labs, ARM MTE & Apple MIE: How Hardware Memory Tagging
  Reveals Invisible iOS Kernel Vulnerabilities (2026-06-10)
  https://www.jamf.com/blog/arm-mte-apple-mie-memory-safety-ios-kernel-vulnerability-research/
- S7: 8kSec, MIE on iOS Deep Dive. Part 1 (kernel via Binary Ninja):
  https://8ksec.io/mie-deep-dive-kernel
  Part 2 (enabling apps + crash analysis):
  https://www.8ksec.io/mie-deep-dive-enabling-apps/
- S16: DFF (Jonathan Levin), SPTM - The Last Bits (tag storage page type,
  kernel.development.t8142 KDK 26.2 MTE insights)
  https://df-f.com/blog/sptm4
- S22: securitycryptographywhatever podcast, Apple's Memory Integrity
  Enforcement (2025-10-31), EMTE = MTE4 discussion
  https://securitycryptographywhatever.com/2025/10/31/apple-mie
- S23: Hexacon 2025 keynote, Ivan Krstic (security engineering context)
- S24: OBTS v8, Jonathan Levin, Make XNU Great Again (SPTM page types)
  https://objectivebythesea.org/v8/talks/OBTS_v8_jLevin.pdf

## Academic

- S12: Google Project Zero, MTE As Implemented, parts 1-3 (Mark Brand,
  2023). Summary + links:
  https://projectzero.google/2023/08/summary-mte-as-implemented.html
  Part 1 (implementation testing):
  https://projectzero.google/2023/08/mte-as-implemented-part-1.html
  Part 2 (mitigation case studies):
  https://projectzero.google/2023/08/mte-as-implemented-part-2-mitigation.html
  Part 3 (the kernel):
  https://projectzero.google/2023/08/mte-as-implemented-part-3-kernel.html
  First handset (Pixel 8, sync-MTE on):
  https://projectzero.google/2023/11/first-handset-with-mte-on-market.html
- S13: TikTag: Breaking ARM's MTE with Speculative Execution (arXiv
  2406.08719)
  https://arxiv.org/abs/2406.08719
- S14: VUSec, StickyTags
  https://www.vusec.net/projects/stickytags/
- S15: Steffin and Classen, Modern iOS Security Features: A Deep Dive into
  SPTM, TXM, and Exclaves (arXiv 2510.09272, 2025-10)
  https://arxiv.org/abs/2510.09272

## ARM specs

- S8: ARM, Introduction to the Memory Tagging Extension
  https://developer.arm.com/documentation/108035/0100/Introduction-to-the-Memory-Tagging-Extension
- S9: ARM, Armv8.9 architecture extension (EMTE / MTE4 features)
  https://developer.arm.com/documentation/109697/0100/Feature-descriptions/The-Armv8-9-architecture-extension

## OS references (Linux / Android)

- S10: Linux kernel docs, MTE in AArch64
  https://docs.kernel.org/arch/arm64/memory-tagging-extension.html
- S11: AOSP docs, Arm Memory Tagging Extension (async/asymmetric guidance)
  https://source.android.com/docs/security/test/memory-safety/arm-mte

## Hardware

- S17: Wikipedia, Apple A19 / A19 Pro (Tilos/Thera, T8150, specs)
  https://en.wikipedia.org/wiki/Apple_A19
- S18: NotebookCheck, Apple A19 Pro (SLC sizes, clocks, memory controller)
  https://www.notebookcheck.net/Apple-A19-Pro-Processor-Benchmarks-and-Specs.1126974.0.html

## Commentary

- S19: Privacy Guides / Jonah Aragon, Memory Integrity Enforcement Changes
  the Game on iOS (2025-09-20)
  https://www.privacyguides.org/posts/2025/09/20/memory-integrity-enforcement-changes-the-game-on-ios
- S20: HackTricks, Memory Tagging Extension (instructions, granule math)
  https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/memory-tagging-extension-mte.html

## Field bugs and crashes (GitHub, added 2026-08-31, see
[09-mte-bugs-field](../docs/09-mte-bugs-field.md))

- S25: FuturaeKit iPhone 17e crash, EXC_ARM_MTE_TAGCHECK_FAIL
  (Futurae-Technologies/ios-sdk #64, open)
  https://github.com/Futurae-Technologies/ios-sdk/issues/64
- S26: GrapheneOS Vanadium MTE crash (Vanadium #1223, open)
  https://github.com/GrapheneOS/Vanadium/issues/1223
- S27: macOS 27 beta SwiftUI weak-table MTE fault, FB23066215
  (cypherair #499, closed; root-caused Apple framework bug)
  https://github.com/cypherair/cypherair/issues/499
- S28: Go runtime MTE crash, indexbyte past granule (cake-tech/cake_wallet
  #2921, closed dup; golang/go#59090)
  https://github.com/cake-tech/cake_wallet/issues/2921
  https://github.com/golang/go/issues/59090
- S29: ZeroTier fails to launch on macOS 26.1 (ZeroTierOne #2540, open,
  MTE-unconfirmed)
  https://github.com/zerotier/ZeroTierOne/issues/2540
- S30: sentry-cocoa: run sample apps with enhanced security capability
  (#5412, open)
  https://github.com/getsentry/sentry-cocoa/issues/5412
- S31: godot C#/.NET iOS 26 XZone allocator trap, heap corruption detected
  by type-aware allocator (#121736, closed)
  https://github.com/godotengine/godot/issues/121736
- S32: fluffychat: request checked-allocations entitlement for MIE
  (krille-chan/fluffychat #2301, open)
  https://github.com/krille-chan/fluffychat/issues/2301
- S33: react-native libgojni.so MTE crash on Pixel 8 Pro
  (facebook/react-native #44276, closed)
  https://github.com/facebook/react-native/issues/44276
- S34: MTE experiments on Apple Silicon macOS (gulmezmerve/mte-examples)
  https://github.com/gulmezmerve/mte-examples

## 2026 developments (added 2026-08-31)

- S35: Calif blog, First public macOS kernel memory corruption exploit on
  Apple M5. Data-only LPE surviving MIE, CVE-2026-28952 (fixed macOS
  26.5). Full 55-page report withheld until patch adoption.
  https://blog.calif.io/p/first-public-kernel-memory-corruption
- S36: 9to5Mac, Anthropic Mythos helped Calif build a macOS exploit in
  five days (2026-05-14)
  https://9to5mac.com/2026/05/14/calif-team-details-how-anthropic-mythos-helped-build-a-working-macos-exploit-in-five-days/
- S37: byteiota, Apple M5 MIE kernel exploit details: _zalloc_ro_mut
  overflow, data-only chain, no tag exception ever triggered
  https://byteiota.com/apple-m5-mie-kernel-exploit-update-to-macos-26-5-now/
- S38: octet-stream.net (Tom Bull), Experiments with Memory Integrity
  Enforcement (2025-12-16): hands-on A19/M5 MIE experiments, heap
  overflow / UAF demos
  https://octet-stream.net/b/scb/2025-12-16-experiments-with-memory-integrity-enforcement.html
- S39: ChipWise, Apple A19 Pro die shot analysis (N3P, ~25-30B
  transistors, floorplan)
  https://chipwise.tech/our-portfolio/apple-a19pro-die-shot-analysis/
- S40: TechPowerUp, A19 Pro & A19 die size analysis (98.6 mm2 vs 105
  mm2 A18 Pro, ~10% smaller; 32KB cache macro doubling)
  https://www.techpowerup.com/344025/apple-a19-pro-a19-die-size-analysis-indicates-9-10-smaller-than-a18-models
- S41: TechInsights, Apple A19 Pro SoC (TSMC N3P) floorplan analysis,
  TMUA28 die (paywalled)
  https://www.techinsights.com/blog/apple-a19-pro-soc-tsmc-n3p-floorplan-analysis
- S42: Apple libmalloc open source, doc/xzone_malloc.md (official XZone
  design: bucketed type isolation, TINY/SMALL/LARGE/HUGE, mimalloc
  derivation)
  https://github.com/apple-oss-distributions/libmalloc/blob/main/doc/xzone_malloc.md
- S43: Apple Xcode docs, Adopting type-aware memory allocation
  (malloc_type_* API, compiler-rewritten malloc)
  https://developer.apple.com/documentation/xcode/adopting-type-aware-memory-allocation
- S44: df-f.com (Jonathan Levin), Darwin: libsystem_malloc .dylib and
  XZone (memento introspection of live XZone, zone/bucket internals)
  https://df-f.com/blog/darwin-libsystem-malloc-dylib-and-xzone
- S45: darknavy.org, Strengthening the Shield: MTE in Heap Allocators
  (glibc/scudo/mimalloc MTE implementations compared)
  https://www.darknavy.org/blog/strengthening_the_shield_mte_in_memory_allocators
- S46: Folded-Tag: Enhancing memory safety with efficient
  hardware-supported memory tagging (Computers & Security 2025)
  https://www.sciencedirect.com/science/article/abs/pii/S0167404825005115
- S47: IUBIK: Isolating User Bytes in Commodity OS Kernels via Memory
  Tagging Extensions (IEEE S&P 2025)
  https://www.computer.org/csdl/proceedings-article/sp/2025/223600a039/21B7QrWwN20
- S48: NanoTag: Systems Support for Efficient Byte-Granular Overflow
  Detection on ARM MTE (IEEE S&P 2026)
- S49: ARM MTE Performance in Practice (arXiv 2601.11786, extended)
  https://arxiv.org/html/2601.11786v1
- S50: pbxscience, iOS 27 sandbox escape resurfaces Filza talk (claims
  of MobileGestalt exploit on iPhone 17 questioned; MIE context)
  https://pbxscience.com/ios-27-sandbox-escape-resurfaces-filza-talk-but-the-iphone-17-story-isnt-what-it-seems
- S51: sigreturn.com, Apple internals #9: SPTM, TXM and memory tagging
  (guarded levels, endpoint tables, PPL/TXM/SPTM generation table,
  Spectre V1 25+ chain figure, XNU_TAG_STORAGE ownership)
  https://sigreturn.com/blog/sptm-txm-memory-tagging/

## 2026 exploits, CVEs and field crashes (GitHub sweep, added 2026-09-18)

- S52: Indegosblade/pmap-tte-remove: XNU pmap_tte_remove physical UAF via
  uint16 pt_desc refcount overflow. 65,537 MAP_SHARED mappings wrap the
  refcount, one munmap frees an L3 page table with 64 live PTEs. Write
  through 64/64 on A13 (15.5), A17 Pro (26.4), A19 (26.0, MIE on).
  Bounty closed 2026-04-26 as "expected behavior" + program warning
  2026-04-27. PoC sources, kernelcache diffs and per-version patch table
  in repo. MITIGATED-NOT-FIXED through 26.6b1 (uint16 never widened).
  https://github.com/Indegosblade/pmap-tte-remove
- S53: Jocala/eqvol issue #1 (2026-09-18): M5 Max, macOS 26.7 (25G229),
  coreaudiod driver-host process killed by MTE tag check, MTE_FAIL code
  262, 7/7 attempts, tag byte varies run to run, address inside live
  MALLOC_SMALL region. Full .ips attached.
  https://github.com/Jocala/eqvol/issues/1
- S54: ironpeak.be (Niels Hofmans), Pardon MIE? (2026-05-23): the
  CVE-2026-28952 fix at instruction level. _zalloc_ro_mut pre/post
  bounds-check asm, why the stack-area filter wrapped, sibling
  RO-zone-writer hunt list, Linux/Android/P0 "side channel" tangents.
  https://ironpeak.be/blog/bypassing-apple-mie/
- S55: blacktop/ipsw-diffs (846 stars): generated per-build symbol diff
  corpus for every IPSW transition. Source for the MTE crash-reporting
  timeline (26.0 beta 9 23A5336a .vs 26.0 RC 23A340, and 26.5 23F77 .vs
  27.0 beta 1 24A5355q).
  https://github.com/blacktop/ipsw-diffs
- S56: xybp888/iOS-SDKs: mirror of iOS SDK header trees. iPhoneOS26.4.sdk
  and iPhoneOS27.0.sdk mach/arm/exception.h define
  EXC_ARM_MTE_TAGCHECK_FAIL 0x106 and EXC_ARM_MTE_CANONICAL_FAIL 0x107.
  https://github.com/xybp888/iOS-SDKs
- S57: khanhduytran0/coruna (702 stars): the leaked Coruna exploit
  toolkit, deobfuscated and rehosted. Per-device WebKit chain table
  (15.4.1 jacurutu, 16.5 terrorbird, 17.0 cassowary).
  https://github.com/khanhduytran0/coruna
- S58: Rat5ak/CORUNA_TECHNICAL_ANALYSIS + CORUNA_IOS-MACOS_FULL_DUMP:
  teardown of the kit and recovered samples (28 JS modules, 6 Wasm,
  13 ARM64 binaries).
  https://github.com/Rat5ak/CORUNA_TECHNICAL_ANALYSIS
- S59: Billy-Ellis/coruna-buffout: WIP reimplementation of the buffout
  WebKit exploit from the kit.
  https://github.com/Billy-Ellis/coruna-buffout
- S60: Hetyey/Coruna: Coruna kernel exploit + PPL/SPTM bypass
  reimplemented in Objective-C (iPhone 13, iOS 17.0). GPU-firmware
  power_thread redirect, hibernate_uat TTBR1 swap,
  __arm_arch_resume_uat raw TTBR load -> broad physical write.
  https://github.com/Hetyey/Coruna
- S61: IvanIVGrozny/Coruna-SPTM-Bypass-RE: interface and internal
  offsets of the kit's SPTM-bypass dylib (coruna_driver vtable,
  kread/kwrite primitives, chip fingerprint fields).
  https://github.com/IvanIVGrozny/Coruna-SPTM-Bypass-RE
- S62: alfiecg24/Titan (165 stars): PPL + SPTM bypass for iOS 16.1 -
  17.4b3 on A14-A17, built on the Coruna Rocket exploit. AGX ROP,
  microPPL bypass, self-referencing AP PTE. Notes that Coruna's ipc_port
  steal was patched in iOS 26 by adding data PAC to ip_nsrequest.
  https://github.com/alfiecg24/Titan
- S63: NeKroFR/RISC-V-MIE: Apple MIE primitives reimplemented on a
  custom RV32IM core (PAC with QARMA-64-5, PMP, KTRR; APRR/GXF planned).
  Useful as a clean-room model of what the hardware layer enforces.
  https://github.com/NeKroFR/RISC-V-MIE
- S64: itspolly/kalloc-type-rs: XNU-derived typed-allocator and zone
  allocator sources republished under APSL-2.0 (kalloc_type views,
  fixed-size slabs, distributed bitmaps, per-zone magazines, opt-in
  poisoning/quarantine). Reference for allocator-level reasoning.
  https://github.com/itspolly/kalloc-type-rs
- S65: Apple security content pages, used for CVE attribution and
  kernel-section counts. macOS Tahoe 26.5 (CVE-2026-28952 credited to
  Calif.io in collaboration with Claude and Anthropic Research;
  CVE-2026-28951 to Csaba Fitzl). iOS 26.6 released 2026-07-27,
  iOS 26.6.1 2026-08-17, iOS 26.7 and iOS 27 2026-09-14. No advisory in
  the 2026 set mentions Memory Integrity Enforcement or tagged memory.
  https://support.apple.com/en-us/127115
  https://support.apple.com/en-us/128066
  https://support.apple.com/en-us/148282
  https://support.apple.com/en-us/149041
  https://support.apple.com/en-us/149034
- S66: Google Threat Intelligence Group, Coruna: The Mysterious Journey
  of a Powerful iOS Exploit Kit (2026-03-03). Five full iOS chains, 23
  exploits, iOS 13.0 - 17.2.1. WebKit RCE CVE-2024-23222 delivered
  in-the-wild. Operators: surveillance-vendor customer, UNC6353
  (Ukraine watering holes), UNC6691 (Chinese scam sites). Kit is not
  effective against current iOS.
  https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit

## A19 firmware and kernelcaches (added 2026-09-18)

- S67: Apple IPSW kernelcache for iPhone18,1 (iPhone 17 Pro), iOS 26.6.1
  build 23G83. Entry `kernelcache.release.v53`, IM4P + LZFSE,
  22,035,992 bytes -> 72,712,192-byte Mach-O, 298 fileset kexts,
  KernelManagement_host-487.100.11. Fetched 2026-09-18 via the ipsw.me
  API + W0lfSword `scripts/fetch_kernelcache.py` (ranged zip64 read of
  the entry, no full IPSW download) and `pyimg4 im4p extract --lzfse`.
  Local copy gitignored; findings in
  [11-t8150-kernelcache](../docs/11-t8150-kernelcache.md).
  https://api.ipsw.me/v4/device/iPhone18,1?type=ipsw
  https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75048/DA1909FD-EE14-421B-BB9C-A85335254485/iPhone18,1_26.6.1_23G83_Restore.ipsw
