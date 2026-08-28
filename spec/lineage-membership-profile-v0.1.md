# T-Trace Lineage Membership / Selective Historical Disclosure Profile v0.1

**Status:** Draft profile  
**Scope:** selective disclosure of one verified reconciliation cycle from a compacted lineage

## 1. Purpose

The Repeated Lineage Compaction Profile keeps the active causal tip bounded by
rolling a fixed-shape `LineageAccumulatorRef` forward after every verified
fork/reconciliation cycle.

That rolling hash chain is intentionally compact, but it is not membership-friendly.
To prove that an old cycle belongs to the current lineage directly from the rolling
chain, a prover would otherwise need to reveal every later accumulator.

This profile adds a companion commitment:

```text
validated cycle commitments
        ↓
canonical Merkle tree
        ↓
LineageMembershipAnchor
        ↓
selected cycle + O(log n) sibling hashes
```

The central rule is:

> **A selected historical reconciliation may be disclosed and verified without disclosing every intervening cycle, provided the membership root is bound to the current validated lineage accumulator.**

This is selective disclosure, not zero-knowledge proof.

## 2. Relationship to existing profiles

The layering is:

```text
Portable Causality Profile
        ↓
Repeated Lineage Compaction Profile
        ↓
Lineage Membership / Selective Disclosure Profile
```

This profile does not replace `LineageAccumulatorRef` and does not change its
13-field shape.

The rolling accumulator remains the active causal commitment. The new
`LineageMembershipAnchor` is a companion object designed for efficient historical
membership proofs.

## 3. Fractal Causal Refactoring diagnosis

The visible problem was proof size:

```text
prove cycle 2 from cycle 20
        ↓
reveal cycles 3 ... 20
```

The deeper model error would be to force one primitive to serve two different
purposes:

```text
rolling active-state commitment
        ≠
historical membership index
```

The repair therefore keeps the fixed-shape rolling root and adds a separate
membership-friendly commitment.

## 4. Validated cycle record

Before a membership anchor is built, the producer MUST validate the complete
retained cycle sequence.

Each retained cycle record contains:

```text
cycle_index
common_state_ref
reconciliation
lineage_accumulator
```

For every cycle, the producer MUST verify:

1. cycle indexes are contiguous and begin at `1`;
2. the common `StateRef` is valid;
3. the two-parent reconciliation is independently revalidated;
4. the lineage accumulator has the exact v0.1 shape and a valid rolling root;
5. the accumulator cycle counter equals the record index;
6. the accumulator binds the reconciliation result state;
7. the accumulator binds the complete reconciliation object;
8. the accumulator's `cycle_commitment_sha256` equals the recomputed cycle summary;
9. cycle `1` has zero predecessor accumulator/root digests;
10. every later cycle binds the exact previous accumulator digest and lineage root;
11. trust domain, logical state identity, and compaction contracts remain continuous;
12. the last retained accumulator is byte-identical to the supplied current accumulator.

The membership root MUST NOT be built from an unvalidated list of arbitrary hashes.

## 5. Cycle commitment

The cycle summary is the same canonical summary used by the Repeated Lineage
Compaction Profile:

```json
{
  "schema": "ttrace-lineage-cycle-summary/v0.1",
  "cycle_index": 2,
  "common_state_ref_sha256": "...",
  "fork_causal_epoch": 3,
  "reconciled_causal_epoch": 4,
  "branch_tip_set_sha256": "...",
  "parent_set_sha256": "...",
  "reconciliation_ref_sha256": "...",
  "result_state_ref_sha256": "...",
  "receipt_sha256": "...",
  "reconciliation_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

The cycle commitment is:

```text
cycle_commitment_sha256 = sha256(canonical_json(cycle_summary))
```

## 6. Membership leaf

A Merkle leaf commits both the one-based cycle index and its cycle commitment:

```json
{
  "schema": "ttrace-lineage-membership-leaf/v0.1",
  "cycle_index": 2,
  "cycle_commitment_sha256": "..."
}
```

The leaf hash is the SHA-256 digest of the canonical JSON object.

Binding the index prevents the same cycle commitment from being moved to another
position without changing the root.

## 7. Internal node

An internal node is:

```json
{
  "schema": "ttrace-lineage-membership-node/v0.1",
  "left_sha256": "...",
  "right_sha256": "..."
}
```

The node hash is the SHA-256 digest of the canonical JSON object.

Leaf and internal-node schemas provide domain separation.

## 8. Tree construction

Version 0.1 uses:

```text
pairwise-duplicate-last-sha256/v0.1
```

Rules:

1. leaves are ordered by contiguous `cycle_index`;
2. adjacent hashes are combined left-to-right;
3. when a level has an odd final node, that node is duplicated as its own right sibling;
4. levels are repeated until one root remains;
5. tree size is committed separately in the anchor and proof.

This algorithm is deterministic. Reordering cycles changes the root.

## 9. LineageMembershipAnchor

The fixed-shape anchor contains:

```text
schema
trust_domain
logical_state_id
completed_reconciliation_cycles
current_causal_epoch
current_accumulator_sha256
current_lineage_root_sha256
current_cycle_commitment_sha256
tree_size
tree_algorithm
cycle_commitment_merkle_root_sha256
membership_contract_sha256
authorization_contract_sha256
```

The anchor MUST bind:

- the exact current validated `LineageAccumulatorRef`;
- the current rolling lineage root;
- the current cycle commitment;
- the number of completed cycles;
- the canonical Merkle root;
- the membership and authorization contracts.

The current cycle commitment is repeated explicitly so the Merkle tree tip and the
active accumulator tip cannot silently disagree.

## 10. Membership proof

A membership proof contains:

```text
anchor_sha256
cycle_index
leaf_index
tree_size
tree_algorithm
cycle_commitment_sha256
leaf_sha256
sibling_path
```

Each sibling entry is:

```json
{
  "side": "left | right",
  "sha256": "..."
}
```

The path length is determined by `tree_size`. Missing and extra siblings MUST be
rejected.

For an odd duplicated final node, the first right sibling MUST equal the current
node hash. A verifier MUST reject a substituted value.

## 11. Selective disclosure package

A v0.1 disclosure contains only:

```text
LineageMembershipAnchor
current LineageAccumulatorRef
one disclosed cycle
one membership proof
```

The disclosed cycle includes:

```text
cycle_index
common_state_ref
portable reconciliation
selected lineage accumulator
cycle summary
cycle commitment
```

The selected reconciliation is fully revalidated. The selected accumulator is
also revalidated and MUST bind the same reconciliation, result state, cycle index,
and cycle commitment.

The package MUST NOT include:

```text
all cycle records
intervening reconciliation objects
raw provider IDs
raw authority IDs
raw provenance digests
branch evidence observations
reconciliation vote evidence
```

The portable reconciliation itself remains provider-free under the Portable
Causality Profile.

## 12. Verification algorithm

A conforming verifier MUST:

1. validate the current lineage accumulator;
2. validate the exact anchor schema;
3. bind the anchor to the current accumulator digest and rolling lineage root;
4. require `tree_size == completed_reconciliation_cycles`;
5. bind the proof to the exact anchor digest;
6. require `leaf_index == cycle_index - 1`;
7. validate the disclosed common state;
8. independently revalidate the disclosed two-parent reconciliation;
9. recompute the cycle summary and cycle commitment;
10. validate the selected cycle's lineage accumulator;
11. bind that accumulator to the selected state, reconciliation, and commitment;
12. recompute the membership leaf;
13. validate every path side and sibling digest;
14. enforce the duplicate-last rule for odd levels;
15. recompute the Merkle root and compare it with the anchor;
16. reject raw evidence or a full-history payload in the disclosure object.

No receipt boolean is trusted without recomputation.

## 13. Complexity and disclosure boundary

For `n` cycles, the sibling path contains approximately:

```text
ceil(log2(n))
```

hashes.

The verifier learns:

- current cycle count;
- current causal epoch and lineage commitment;
- selected cycle index;
- the selected common state and portable reconciliation;
- opaque sibling hashes needed for membership.

The verifier does not receive the semantic contents of intervening cycles.

## 14. Fail-closed conditions

The reference verifier rejects at least:

- malformed or extra fields in anchor, proof, or disclosure objects;
- an invalid current lineage accumulator;
- anchor/current-accumulator disagreement;
- tree-size or tree-algorithm disagreement;
- a proof bound to another anchor;
- non-contiguous cycle indexes during anchor construction;
- a retained cycle that fails reconciliation or accumulator validation;
- historical accumulator predecessor discontinuity;
- a disclosed cycle summary or commitment mismatch;
- a selected accumulator that does not bind the selected reconciliation;
- an incorrect leaf index;
- a missing, extra, reordered, or modified sibling;
- an invalid duplicate-last sibling;
- a Merkle-root mismatch;
- zero membership or authorization contract digests;
- embedded provider evidence or full cycle history.

## 15. Assurance boundary

This profile establishes structural membership of one fully disclosed cycle in a
supplied membership anchor that is bound to a current lineage accumulator.

It does **not** by itself establish:

- authenticity or authorization of an unsigned membership anchor;
- capture completeness or non-bypassable recording;
- availability of undisclosed historical proof material;
- non-equivocation by the anchor producer;
- append-only consistency between two different membership roots;
- zero-knowledge privacy;
- hiding of cycle count or selected cycle index;
- correctness of the domain policy that produced a reconciliation;
- arbitrary N-parent reconciliation;
- indefinite cryptographic durability.

Deployments SHOULD sign or attest the anchor when authority or non-equivocation is
part of the claim.

## 16. Reference implementation

- implementation: `ttrace/lineage_membership.py`
- executable verifier: `scripts/verify_lineage_membership.py`
- tests: `tests/test_lineage_membership.py`
- predecessor profile: `spec/lineage-compaction-profile-v0.1.md`

## 17. Next falsifiable question

**Membership-Root Consistency / Anti-Equivocation v0.1**

Can a later membership root prove that it is an append-only extension of an earlier
root, without replaying every historical cycle and without allowing an anchor
producer to present incompatible histories to different verifiers?
