# T-Trace assurance dimensions

T-Trace separates claims that are often collapsed into a single word such as
"auditable" or "verified".

The L1-L4 labels are convenient names, not a monotonic maturity ladder. Record
integrity, capture completeness, and independent reproducibility are separate
dimensions. For example, an output may be independently reproducible from the
supplied inputs while those inputs still omit a real-world effect.

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

OpenPoC-02 exercises L4 with bound replay recipes, inputs, expected outputs,
and runtime contracts. Its negative fixtures show that successful replay over
an incomplete input does not repair L3.

Verdicts are claim-scoped. `supported-under-stated-assumptions` means the
required checks succeeded under the manifest's declared trust and adversary
model; it is not an unconditional proof of the external world.

## Required language in integrations

Use precise claims:

- Good: "The presented trace is structurally valid."
- Good: "The committed records are tamper-evident under the stated anchor."
- Good: "All relevant effects are required to traverse the attested gate."
- Good: "The claimed relation was reproduced over the exact bound inputs."
- Bad: "The log is complete" when no non-bypassable capture boundary exists.
- Bad: "The action happened" when only an agent-side assertion exists.
- Bad: "The external history is complete" because replay over the supplied
  history succeeded.

No assurance dimension should be inferred from another without an explicit
mechanism, claim scope, adversary model, and trust assumptions.
