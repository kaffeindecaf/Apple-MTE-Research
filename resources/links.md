# External sources

Tagged S1..S50, cited from docs/. Local copies in resources/papers/ are
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
