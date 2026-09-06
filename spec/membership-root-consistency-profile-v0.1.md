# T-Trace Membership-Root Consistency / Anti-Equivocation Profile v0.1

**Status:** Draft profile  
**Scope:** append-only consistency between two lineage-membership roots and bounded detection of conflicting authority statements

## 1. Purpose

The Lineage Membership Profile proves that one disclosed historical reconciliation
cycle belongs to one supplied membership root.

That does not answer a different question:

> Is a later membership root an append-only extension of an earlier root, or did the
> producer replace, reorder, or omit earlier cycle commitments?

This profile adds a compact consistency proof over the **same membership roots**
already defined by `lineage-membership-profile-v0.1.md`.

It also defines a normalized statement format for externally verified signatures or
attestations. When two conflicting statements from the same authority are presented,
a verifier can emit attributable equivocation evidence.

The central rules are:

> **Append-only consistency is a relation between two roots, not a property asserted
> by the later root alone.**

> **Equivocation can be detected only when conflicting authority statements are
> compared. Absence of a presented conflict is not proof of global non-equivocation.**

## 2. Relationship to existing profiles

The profile is layered as follows:

```text
Portable Causality
        ↓
Repeated Lineage Compaction
        ↓
Lineage Membership / Selective Disclosure
        ↓
Membership-Root Consistency / Anti-Equivocation
```

It does not modify:

- the base T-Trace v0.1 JSONL envelope;
- `StateRef`, branch, reconciliation, or receipt objects;
- the 13-field `LineageAccumulatorRef`;
- the existing membership anchor;
- the `pairwise-duplicate-last-sha256/v0.1` membership tree.

The consistency proof reconstructs the existing membership roots directly.

## 3. Problem with replaying full history

A naïve consistency check could disclose all historical cycle commitments:

```text
old commitments
+
new suffix commitments
        ↓
rebuild both roots
```

That proves the relation but scales linearly and defeats bounded disclosure.

Instead, this profile uses a compact frontier of complete power-of-two subtrees.

```text
old root frontier       append-only suffix blocks
      │                           │
      └────────── merge ──────────┘
                    │
                    ▼
               new frontier
                    │
                    ▼
           existing new membership root
```

The proof reveals subtree hashes and two current-tip membership paths. It does not
reveal raw cycle records, reconciliation policies, provider evidence, or intervening
semantic states.

## 4. Cryptographic assumptions

The construction assumes collision resistance and second-preimage resistance of
SHA-256 over the canonical T-Trace JSON encodings.

No claim is made if these assumptions fail.

All object digests use:

```text
sha256(canonical_json_bytes(object))
```

The consistency construction reuses the membership profile's domain-separated leaf
and node hashes:

```text
ttrace-lineage-membership-leaf/v0.1
ttrace-lineage-membership-node/v0.1
```

## 5. Existing membership-tree semantics

The existing membership tree uses:

```text
pairwise-duplicate-last-sha256/v0.1
```

At each level:

- adjacent nodes are hashed left-to-right;
- if the level has an odd final node, that node is paired with itself.

The consistency verifier MUST reproduce exactly these semantics when reconstructing
an endpoint root.

## 6. Compact frontier

For a tree of `n` leaves, the compact frontier is the canonical left-to-right
decomposition of `[0, n)` into complete power-of-two subtrees.

Example:

```text
n = 13 = 8 + 4 + 1

frontier:
  start=0   size=8
  start=8   size=4
  start=12  size=1
```

Each frontier entry has exactly:

```json
{
  "start": 0,
  "size": 8,
  "sha256": "..."
}
```

Requirements:

- `start` is a non-negative integer;
- `size` is a positive power of two;
- `start` is aligned to `size`;
- blocks are contiguous and non-overlapping;
- the exact block shape is determined by `tree_size`;
- each digest is the membership subtree root for that range.

## 7. Reconstructing a duplicate-last root from the frontier

The rightmost frontier block is raised by self-hashing until it reaches the size of
the block immediately to its left. The two equal-sized roots are then combined.
This repeats from right to left.

Example:

```text
frontier sizes = [8, 4, 1]

1 → self-hash → 2 → self-hash → 4
4-left + 4-right → 8
8-left + 8-right → existing membership root
```

The result MUST equal the endpoint membership anchor's
`cycle_commitment_merkle_root_sha256`.

This is not a new parallel root. It is an alternative compact witness for the
existing root.

## 8. Canonical append blocks

To prove extension from `old_size` to `new_size`, the proof covers exactly:

```text
[old_size, new_size)
```

with canonical aligned power-of-two blocks.

The verifier appends each block to the old frontier. Whenever two adjacent terminal
blocks have equal size, it merges them using the membership node hash.

After all append blocks:

- the resulting frontier shape MUST equal the canonical frontier for `new_size`;
- bagging that frontier MUST reproduce the new membership root.

The proof MUST fail closed on:

- a missing suffix block;
- a duplicated block;
- an overlapping block;
- a gap;
- a changed start offset;
- a non-power-of-two size;
- non-canonical decomposition;
- a changed subtree digest;
- a reordered block set.

## 9. Current-tip membership binding

A root-consistency proof MUST also show that each endpoint's declared current cycle
commitment belongs to that endpoint root.

The proof therefore carries:

```text
old_current_cycle_sibling_path
new_current_cycle_sibling_path
```

For each endpoint, the verifier recomputes:

```text
leaf(
  cycle_index = tree_size,
  cycle_commitment_sha256 = current_cycle_commitment_sha256
)
```

and verifies the exact duplicate-last membership path to the endpoint root.

This prevents an anchor from pairing:

```text
one membership root
+
an unrelated current accumulator / current cycle commitment
```

while still passing the consistency proof.

## 10. Consistency proof object

A v0.1 proof has exactly:

```json
{
  "schema": "ttrace-lineage-root-consistency-proof/v0.1",
  "old_anchor_sha256": "...",
  "new_anchor_sha256": "...",
  "old_tree_size": 3,
  "new_tree_size": 9,
  "membership_tree_algorithm": "pairwise-duplicate-last-sha256/v0.1",
  "consistency_algorithm": "compact-frontier-over-pairwise-duplicate-last-sha256/v0.1",
  "old_frontier": [],
  "append_blocks": [],
  "old_current_cycle_sibling_path": [],
  "new_current_cycle_sibling_path": []
}
```

The proof MUST bind the exact old and new membership-anchor digests.

Unknown fields are rejected.

## 11. Consistency package

A standalone package contains:

```json
{
  "schema": "ttrace-lineage-root-consistency-package/v0.1",
  "old_endpoint": {
    "membership_anchor": {},
    "current_accumulator": {}
  },
  "new_endpoint": {
    "membership_anchor": {},
    "current_accumulator": {}
  },
  "consistency_proof": {}
}
```

Each endpoint is independently validated using the existing membership-anchor and
lineage-accumulator validators.

The two endpoints MUST agree on:

- `trust_domain`;
- `logical_state_id`;
- membership contract;
- authorization contract;
- membership tree algorithm.

The later endpoint MUST have:

- a strictly larger tree size;
- a strictly later causal epoch;
- a root reconstructed by appending only the proof's canonical suffix blocks.

## 12. Verification verdict

A successful decision reports:

```text
append_only_consistent          = true
current_tips_membership_bound   = true
raw_cycle_records_disclosed     = false
```

It also reports:

- old and new tree sizes;
- old and new anchor digests;
- old frontier-node count;
- append-block count;
- current-tip sibling-path sizes.

## 13. Normalized authority statements

The consistency proof is structural. Authority is a separate evidence boundary.

A `LineageAnchorStatement` normalizes the result of an external signature,
attestation, or equivalent verifier.

```json
{
  "schema": "ttrace-lineage-anchor-statement/v0.1",
  "verified": true,
  "authority_id": "ed25519-sha256:...",
  "statement_sequence": 2,
  "previous_statement_sha256": "...",
  "statement_provenance_sha256": "...",
  "trust_domain": "example.procurement",
  "logical_state_id": "authorization-state",
  "tree_size": 9,
  "anchor_sha256": "...",
  "membership_root_sha256": "...",
  "tree_algorithm": "pairwise-duplicate-last-sha256/v0.1",
  "membership_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

The `verified` field MUST represent a prior external verification step. The T-Trace
core does not treat an unverified caller assertion as a signature.

The statement binds the complete comparison context: tree algorithm, membership
contract, and authorization contract. Statements from different membership contexts
are not comparable equivocation evidence merely because they share an authority ID.

Sequence rules:

- statement `1` uses the all-zero predecessor;
- later statements require a non-zero predecessor digest;
- a directly authorized consistency transition requires:
  - the same authority;
  - `new_sequence = old_sequence + 1`;
  - `new.previous_statement_sha256 = sha256(old_statement)`.

`verify_authorized_lineage_root_consistency` validates this direct chain but does not
search for conflicting statements. Its `presented_equivocation_detected` field is
therefore always `false` on that path. Call
`detect_lineage_anchor_equivocation` separately for every pair of presented views that
should be compared.

## 14. Bounded equivocation detection

If two externally verified statements from the same authority are presented, the
verifier can detect these conflicts:

### Same-sequence conflict

```text
same authority
same statement sequence
same predecessor statement
different anchor digest
```

### Same-size root conflict

```text
same authority
same trust domain and logical state
same tree algorithm
same membership contract
same authorization contract
same tree size
different membership root
```

The evidence object records both statement and anchor digests.

Detection is attributable only to the supplied verified statements.

## 15. Anti-equivocation claim boundary

A successful authorized transition establishes:

```text
presented old statement
        ↓ direct statement chain
presented new statement
        ↓
append-only root consistency
```

It does **not** establish global non-equivocation.

A producer may have issued another statement to a party whose evidence was not
presented. Detecting that split view requires at least one of:

- gossip between relying parties;
- witness cosigning;
- a transparency log;
- an external consistency monitor;
- another mechanism that compares views.

Accordingly the decision reports:

```text
global_non_equivocation_status = "unproven"
```

This status MUST NOT be rewritten as `false` or `proven` merely because no conflict
appears in the supplied pair.

## 16. Fail-closed conditions

The reference verifier rejects at least:

- malformed endpoint, proof, statement, path, or block shapes;
- unknown proof or statement fields;
- invalid endpoint membership anchors or accumulators;
- equal or decreasing tree sizes;
- namespace, contract, or tree-algorithm drift;
- non-canonical old frontier;
- an old frontier that does not reconstruct the old root;
- non-canonical suffix coverage;
- an append result that does not reconstruct the new root;
- a current-cycle path not bound to its endpoint root;
- an authority change across a direct statement transition;
- statement sequence gaps or replay;
- a successor statement bound to the wrong predecessor;
- unverified authority statements.

## 17. Complexity

For a tree of `n` cycles and an extension of `k` cycles:

- old frontier size is at most `floor(log2(n)) + 1`;
- canonical append-block count is logarithmic in the range decomposition;
- each current-tip path is `O(log n)`;
- no raw cycle record is required by the standalone verifier.

The proof is not zero knowledge. Subtree and sibling hashes may still reveal
linkability or allow dictionary attacks over low-entropy commitments.

## 18. Assurance boundary

This profile establishes, for supplied valid endpoints and proof material:

- structural append-only consistency between two membership roots;
- exact binding of both endpoint current cycles;
- direct continuity of two normalized verified authority statements;
- attributable conflict evidence when both conflicting statements are presented.

It does not by itself prove:

- authenticity of a statement whose external verification was not performed;
- global non-equivocation;
- availability of old cycle evidence;
- capture completeness;
- correctness of reconciliation policy;
- organizational, storage, hardware, or network independence;
- zero-knowledge privacy;
- Byzantine quorum correctness.

## 19. Reference implementation

- implementation: `ttrace/lineage_consistency.py`
- tests: `tests/test_lineage_consistency.py`
- executable verifier: `scripts/verify_lineage_consistency.py`
- membership profile: `spec/lineage-membership-profile-v0.1.md`
- review notes: `docs/lineage-consistency-review-notes.md`
