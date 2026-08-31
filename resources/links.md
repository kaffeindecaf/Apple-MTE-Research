# External sources

Tagged S1..S24, cited from docs/. Local copies in resources/papers/ where
noted. Everything was checked 2026-08-31.

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
