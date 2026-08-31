# Knowledge graph

The minimal neural network: nodes are documents, resources, and local repos.
Edges are typed relationships. Wikilinks in docs/ encode the same edges;
scripts/graph.py verifies them.

## Nodes

    ID           TYPE        LOCATION / URL
    README       doc         README.md
    checklist    doc         checklist.md
    graph        doc         graph.md
    01-mte-basics   doc      docs/01-mte-basics.md
    02-emte         doc      docs/02-emte.md
    03-apple-mie    doc      docs/03-apple-mie.md
    04-xnu-mte      doc      docs/04-xnu-mte.md
    05-allocators   doc      docs/05-allocators.md
    06-a19-hardware doc      docs/06-a19-hardware.md
    07-attack-surface doc    docs/07-attack-surface.md
    08-research-methods doc  docs/08-research-methods.md
    09-mte-bugs-field doc    docs/09-mte-bugs-field.md
    10-exploit-examples doc  docs/10-exploit-examples.md
    links        resource    resources/links.md (S1..S51)
    local-tools  resource    resources/local-tools.md
    papers       resource    resources/papers/ (gitignored, local copies only)
    kernel-deltas  repo      ~/Desktop/kernel-deltas (kcwatch feed, T8150 board candidate)
    W0lfSword      repo      ~/Desktop/W0lfSword (XPF, offsets.m, usbtest, panic analyzer)
    ABBS           repo      ~/Desktop/Apple-Bug-Bounty-Skill (ios-* skills, offsets.yaml)

## Edges

    01-mte-basics   -specifies-> 02-emte
    02-emte         -implemented_by-> 03-apple-mie
    03-apple-mie    -kernel_side-> 04-xnu-mte
    03-apple-mie    -allocator_side-> 05-allocators
    03-apple-mie    -runs_on-> 06-a19-hardware
    04-xnu-mte      -uses-> 05-allocators
    05-allocators   -protected_by-> 04-xnu-mte (SPTM tag storage)
    06-a19-hardware -enables-> 03-apple-mie (EMTE silicon, tag storage)
    07-attack-surface -studies-> 03-apple-mie
    07-attack-surface -studies-> 05-allocators
    08-research-methods -feeds-> 07-attack-surface
    08-research-methods -uses-> local-tools
    08-research-methods -uses-> kernel-deltas
    08-research-methods -uses-> W0lfSword
    09-mte-bugs-field -surveys-> 03-apple-mie (field crash signatures)
    09-mte-bugs-field -feeds-> 07-attack-surface (real bug shapes)
    09-mte-bugs-field -grounded_in-> links (S25..S34)
    10-exploit-examples -details-> 07-attack-surface (P0/TikTag/StickyTags)
    10-exploit-examples -grounded_in-> links (S12, S13, S14)
    01-mte-basics   -grounded_in-> links (S8, S10, S11)
    03-apple-mie    -grounded_in-> links (S1, S2, S3, S4)
    04-xnu-mte      -grounded_in-> links (S5, S15, S16)
    06-a19-hardware -grounded_in-> links (S17, S18)
    kernel-deltas   -tracks-> 06-a19-hardware (T8150 kernelcache deltas)
    W0lfSword       -resolves-> 04-xnu-mte (XPF offsets)
    ABBS            -routes-> 08-research-methods (methodology skills)

## How to use

1. Start at README, jump to [graph](graph.md).
2. Pick a doc by node ID. Follow its links to neighbors.
3. Verify the network stays intact: python3 scripts/graph.py
4. New findings: add or extend a doc, add a checklist item, link it.

## Open edges (research gaps)

    A19 silicon die map      -> 06-a19-hardware   (nobody published tag storage die area)
    tag PRNG stats           -> 04-xnu-mte        (no public measurements)
    TikTag-on-A19 test       -> 07-attack-surface (no independent public test)
    sptm.t8150 tag storage RE -> 04-xnu-mte       (SPTM firmware RE referenced, not published)
