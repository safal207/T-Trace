# T-Trace assurance levels

T-Trace separates claims that are often collapsed into a single word such as
"auditable" or "verified".

| Level | Name | What can be established | What remains outside the level |
|---|---|---|---|
| L1 | Trace validity | Schema, record types, identifier uniqueness, per-thread timestamp ordering, transition/commit causality | Tamper evidence, capture completeness, real-world execution |
| L2 | Record integrity | Presented records belong to an append-only, signed, anchored, or consistency-proved history | Actions that never entered the history |
| L3 | Capture completeness | Relevant effects cannot occur without recorder evidence at a non-bypassable effect point | Independent reproduction of the claimed outcome |
| L4 | Independent reproducibility | A third party has the recipe, inputs, versions, and environment evidence needed to reproduce or falsify the outcome | Broader semantic or policy claims not encoded by the experiment |

## Current implementation boundary

The reference T-Trace validator implements L1 checks. Additional systems may
supply L2 mechanisms such as signed receipts, hash chains, Merkle consistency
proofs, or external anchors.

OpenPoC-01 explores the transition from L2 to L3. It demonstrates that record
integrity cannot establish capture completeness when the effect path is
bypassable.

Future OpenPoCs may explore L4 through replay recipes, environment binding, and
independently reproducible outcomes.

## Required language in integrations

Use precise claims:

- Good: "The presented trace is structurally valid."
- Good: "The committed records are tamper-evident under the stated anchor."
- Good: "All relevant effects are required to traverse the attested gate."
- Bad: "The log is complete" when no non-bypassable capture boundary exists.
- Bad: "The action happened" when only an agent-side assertion exists.

No higher assurance level should be inferred from a lower level without an
explicit mechanism and trust assumptions.
