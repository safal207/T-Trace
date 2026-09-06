# Witness-Policy Handoff Chain Membership-Root Consistency Profile v0.1

Status: Draft

## 1. Purpose

This profile proves that a later witness-policy handoff membership root preserves
an earlier root as an exact append-only prefix. The proof is compact: it carries a
canonical frontier for the old tree, canonical subtree blocks for the appended
range, and membership paths for the current step at both endpoints.

The profile also defines:

- context-bound statements from an external anchor authority;
- direct continuity between two such statements; and
- bounded evidence when two presented statements from the same authority conflict.

It extends the repeated handoff-chain and handoff-chain membership profiles. It
does not change the base T-Trace v0.1 record format.

## 2. Assurance boundary

A successful standalone consistency verification proves all of the following:

1. both endpoint membership anchors are structurally valid and bind their supplied
   current handoff-chain references;
2. the old frontier reconstructs the old membership root;
3. the canonical append blocks transform that frontier into the later root;
4. the final step commitment of each endpoint is a member of that endpoint root;
5. both endpoints use the same chain, genesis, tree algorithm, and all four
   contract planes.

It does not independently prove any of the following:

- semantic validity of undisclosed handoff packages;
- freshness of either current handoff-chain reference;
- authorization of either membership anchor;
- rolling-chain descendance of the later current reference from the earlier one;
- absence of statements or roots that were not presented to the verifier; or
- global non-equivocation.

The builder validates both full retained histories and requires the later retained
history to contain the exact earlier boundary reference. Those builder checks are
not encoded as an independent claim in the compact serialized proof.

## 3. Domain constants

```text
proof schema
  ttrace-witness-policy-handoff-chain-membership-root-consistency-proof/v0.1

package schema
  ttrace-witness-policy-handoff-chain-membership-root-consistency-package/v0.1

anchor statement schema
  ttrace-witness-policy-handoff-chain-membership-anchor-statement/v0.1

equivocation evidence schema
  ttrace-witness-policy-handoff-chain-membership-anchor-equivocation-evidence/v0.1

consistency algorithm
  compact-frontier-over-pairwise-duplicate-last-sha256/v0.1
```

The membership tree algorithm remains:

```text
pairwise-duplicate-last-sha256/v0.1
```

Leaf and internal-node hashes MUST use the domain objects defined by the
handoff-chain membership profile. Implementations MUST NOT substitute lineage
cycle leaf or node domains.

## 4. Consistency package

The package has exactly four fields:

```json
{
  "schema": "ttrace-witness-policy-handoff-chain-membership-root-consistency-package/v0.1",
  "old_endpoint": {
    "membership_anchor": {},
    "current_chain_ref": {}
  },
  "new_endpoint": {
    "membership_anchor": {},
    "current_chain_ref": {}
  },
  "consistency_proof": {}
}
```

Each endpoint has exactly `membership_anchor` and `current_chain_ref`. The anchor
MUST validate against that exact reference under the handoff-chain membership
profile.

The proof has exactly these fields:

```json
{
  "schema": "ttrace-witness-policy-handoff-chain-membership-root-consistency-proof/v0.1",
  "old_anchor_sha256": "<sha256>",
  "new_anchor_sha256": "<sha256>",
  "old_tree_size": 3,
  "new_tree_size": 9,
  "membership_tree_algorithm": "pairwise-duplicate-last-sha256/v0.1",
  "consistency_algorithm": "compact-frontier-over-pairwise-duplicate-last-sha256/v0.1",
  "old_frontier": [],
  "append_blocks": [],
  "old_current_step_sibling_path": [],
  "new_current_step_sibling_path": []
}
```

No raw handoff package appears in this object.

### 4.1 Block shape

Each frontier or append block has exactly:

```json
{
  "start": 0,
  "size": 2,
  "sha256": "<subtree-root-sha256>"
}
```

`start` MUST be a non-negative JSON integer. `size` MUST be a positive power-of-two
JSON integer. Booleans and floating-point values MUST be rejected even where a
host language considers them numerically equal to an integer.

### 4.2 Path shape

Each sibling path entry has exactly:

```json
{"side": "left", "sha256": "<sha256>"}
```

`side` MUST be `left` or `right`. For an odd last node, the duplicate-last sibling
MUST equal the current hash exactly.

## 5. Canonical compact frontier

For a tree of size `n`, the old frontier is the left-to-right binary decomposition
of `[0,n)`, greedily taking the largest power-of-two subtree at each position.

Examples:

```text
n = 1  -> (0,1)
n = 3  -> (0,2), (2,1)
n = 7  -> (0,4), (4,2), (6,1)
```

The append range `[old_size,new_size)` is decomposed from left to right. At a
nonzero cursor the next block starts with the largest aligned power of two, reduced
until it fits in the remaining suffix.

Example for `3 -> 9`:

```text
old frontier  (0,2), (2,1)
append blocks (3,1), (4,4), (8,1)
```

The verifier MUST reject missing, extra, reordered, unaligned, overlapping, or
noncanonical blocks.

## 6. Root reconstruction

To reconstruct the duplicate-last Merkle root from the old frontier:

1. initialize the accumulator with the rightmost frontier block;
2. moving right-to-left, duplicate the accumulator until its subtree size equals
   the next block size;
3. hash the next block on the left with the accumulator on the right;
4. continue until one root remains.

Each append block is then added to the frontier. Adjacent equal-sized, aligned
blocks MUST merge with the membership profile's internal-node hash. After all
append blocks, the resulting frontier MUST have the canonical prefix shapes for
`new_tree_size`, and its bagged root MUST equal the later membership root.

## 7. Verification algorithm

A verifier MUST fail closed unless every step succeeds:

1. require exact package, endpoint, proof, block, and path shapes;
2. validate each endpoint anchor against its supplied current chain reference;
3. require strict positive integer old and new sizes and `old_size < new_size`;
4. bind both proof sizes and both anchor digests;
5. require the specified membership and consistency algorithms;
6. require equality across these endpoint context fields:
   - `chain_id`;
   - `policy_id`;
   - `genesis_policy_epoch`;
   - `genesis_policy_sha256`;
   - `tree_algorithm`;
   - `chain_contract_sha256`;
   - `chain_authorization_contract_sha256`;
   - `membership_contract_sha256`;
   - `authorization_contract_sha256`;
7. require anchor handoff counts to equal their tree sizes and the later current
   policy epoch to be greater than the earlier epoch;
8. reconstruct and compare the old root;
9. append and merge every canonical suffix block;
10. reconstruct and compare the new root;
11. verify membership of the earlier current-step commitment at `old_size - 1`;
12. verify membership of the later current-step commitment at `new_size - 1`.

Malformed recursion, unexpected types, unknown fields, missing fields, and invalid
numeric representations MUST produce a negative decision rather than an uncaught
exception.

On success the decision reason is:

```text
witness_policy_handoff_chain_membership_root_consistency_verified
```

The decision MUST expose these explicit non-claims:

```text
raw_handoff_packages_disclosed       false
membership_anchor_authorization_status  not-evaluated
current_tip_freshness_status         not-evaluated
rolling_chain_descendance_status     not-independently-proven
global_non_equivocation_status       unproven
```

## 8. Builder requirements

The canonical builder MUST:

1. strictly validate both contract digests;
2. rebuild and validate both complete retained handoff histories;
3. require `old_size < new_size`;
4. require every old step commitment to equal the corresponding prefix commitment
   in the later history; and
5. require the later history's reference at the old boundary to be
   canonical-byte-identical to the supplied old current chain reference.

The builder MUST verify its completed package before returning it.

## 9. Authority statements

An authority statement has exactly these fields:

```text
schema, verified, authority_id, statement_sequence,
previous_statement_sha256, statement_provenance_sha256,
chain_id, policy_id, genesis_policy_epoch, genesis_policy_sha256,
tree_size, anchor_sha256, membership_root_sha256,
current_chain_ref_sha256, current_chain_root_sha256,
current_step_commitment_sha256, current_policy_epoch, current_policy_sha256,
tree_algorithm, chain_contract_sha256,
chain_authorization_contract_sha256, membership_contract_sha256,
authorization_contract_sha256
```

The statement MUST bind every listed endpoint field exactly. `verified` MUST be the
JSON boolean `true`; this field records a result obtained outside this profile and
does not create authorization by itself. `authority_id` MUST be nonempty.

`statement_sequence` MUST be a strict positive JSON integer. Sequence 1 MUST use
the all-zero SHA-256 predecessor. Later sequences MUST use a nonzero SHA-256
predecessor. `statement_provenance_sha256` MUST be nonzero.

An authorized consistency transition additionally requires:

- the same authority identifier;
- `new_sequence = old_sequence + 1`; and
- `new.previous_statement_sha256 = SHA256(canonical(old_statement))`.

Success reports direct presented statement continuity only. It does not perform an
equivocation search.

## 10. Presented-view equivocation

Two statements are comparable only when they have the same authority and the same
chain, policy, genesis, tree algorithm, and all four contract planes.

Two detection modes are defined:

```text
same-sequence-conflict
  same statement sequence and predecessor, but different anchor digest

same-size-root-conflict
  same tree size, but different membership root
```

Different authorities or contexts do not prove equivocation. A non-conflicting
comparison may return a canonical diagnostic with reason:

```text
witness_policy_handoff_chain_membership_anchor_equivocation_not_proven
```

When a conflict is detected, the evidence object contains exact pair digests,
sizes, roots, the shared comparison context, detection mode, and:

```text
verified                       true
equivocation_detected          true
global_non_equivocation_status unproven
```

For noncomparable pairs, shared context fields are `null`; pair-specific digests,
sizes, and roots remain diagnostic.

## 11. Standalone evidence validation

A serialized evidence object MUST NOT be trusted from shape alone. The standalone
validator receives both anchors, both current references, and both statements as
pinned inputs. It MUST:

1. require the exact evidence shape and detected-conflict constants;
2. revalidate both statements against their endpoints;
3. rerun the equivocation detector;
4. require an actual conflict; and
5. compare the supplied evidence to the regenerated evidence using canonical JSON
   bytes.

An identical or nonconflicting pair MUST NOT validate as serialized equivocation
evidence.

## 12. Complexity and disclosure

For an old size `m` and later size `n`, frontier and append block counts are
logarithmic in the binary decompositions of the covered ranges. Each current-step
path is `O(log n)`. Verification time and proof size are therefore bounded by the
number of compact blocks and sibling hashes rather than the number or byte size of
hidden handoff packages.

Endpoint anchors and current chain references remain disclosed. The proof does not
hide their chain identifiers, policy identifiers, epochs, contract digests, roots,
or current step commitments.

## 13. Next assurance gate

The next layer is Witness-Policy Handoff Membership-Root Gossip / Split-View
Detection v0.1: independent observers exchange signed anchor statements and
present conflicts across views. That layer can improve split-view discovery, but
must still distinguish evidence for presented conflicts from universal completeness
or global non-equivocation.
