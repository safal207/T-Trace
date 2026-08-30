# T-Trace Witness-Policy Handoff-Chain Membership / Selective Disclosure Profile v0.1

**Status:** Draft profile
**Scope:** selective disclosure of one verified witness-policy rotation from a validated handoff chain

## 1. Purpose

The Repeated Witness-Policy Handoff Chain Profile keeps the accepted policy tip
fixed-shape by rolling one `WitnessPolicyHandoffChainRef` forward after every
verified dual-quorum handoff.

That rolling commitment is intentionally compact, but it is not
membership-friendly. Proving that an old rotation belongs to a later chain tip
directly from the rolling chain would require revealing every later handoff package
and chain reference.

This profile adds a companion commitment:

```text
validated handoff-chain step commitments
        ↓
canonical Merkle tree
        ↓
WitnessPolicyHandoffChainMembershipAnchor
        ↓
one selected handoff + one predecessor ref + two O(log n) paths
```

The central rule is:

> **One selected policy rotation may be independently revalidated and proven a
> member of a supplied current-tip-bound handoff-chain anchor without disclosing
> every intervening handoff package.**

This is selective disclosure, not a zero-knowledge proof.

## 2. Relationship to existing profiles

The layering is:

```text
Witness-Quorum Anchor
        ↓
Witness-Set Rotation / Dual-Quorum Handoff
        ↓
Repeated Witness-Policy Handoff Chain
        ↓
Handoff-Chain Membership / Selective Disclosure
```

This profile does not replace `WitnessPolicyHandoffChainRef`, change its
eighteen-field shape, or change the direct handoff verifier. The rolling chain
reference remains the active policy-history commitment. The membership anchor is
a companion object optimized for bounded historical disclosure.

The membership root is not derivable from the rolling chain root alone. A producer
that wants selective disclosure retains the validated step commitments or another
authenticated mechanism capable of reproducing the same Merkle tree.

## 3. Fractal Causal Refactoring diagnosis

The visible problem is proof size:

```text
prove handoff 2 from handoff 20
        ↓
reveal handoffs 3 ... 20
```

The deeper model error would be to make one primitive serve two different jobs:

```text
rolling active-tip commitment
        ≠
historical membership index
```

The repair keeps the fixed-shape rolling chain unchanged and commits its already
validated step commitments into a separate, domain-separated Merkle tree.

## 4. Cryptographic and canonicalization assumptions

All object digests are:

```text
sha256(canonical_json_bytes(object))
```

The construction assumes collision resistance and second-preimage resistance of
SHA-256 over the canonical T-Trace JSON encoding. No claim survives a failure of
those assumptions.

Leaf and internal-node schemas are distinct from each other and from the lineage
membership schemas. A digest from another T-Trace tree cannot be silently reused
as a handoff-chain leaf or node.

## 5. Validated handoff package sequence

An anchor producer MUST validate the complete retained handoff-package sequence
before it builds the Merkle root. The public builder accepts only the ordered
complete `handoff_packages` and the supplied `current_chain_ref`; intermediate
indexes, predecessor references, steps, and references are derived by deterministic
replay rather than trusted as caller-provided records.

For the complete retained sequence, the producer MUST:

1. require a non-empty sequence of exact-shape complete handoff packages;
2. require the package count to equal
   `current_chain_ref.completed_handoffs`;
3. assign contiguous handoff indexes beginning at `1`;
4. independently verify every complete dual-quorum handoff package;
5. for index `1`, rebuild the seed from the exact expected chain ID, genesis policy
   epoch/digest, chain contract, and authorization contract copied from the supplied
   current chain reference;
6. for every later index, advance the exact chain reference derived by the previous
   replay step through the existing handoff-chain verifier;
7. thereby enforce epoch continuity, exact activation-package carry-forward,
   previous-reference/root binding, genesis continuity, and contract continuity;
8. require each derived `chain_ref.step_commitment_sha256` to equal the digest of
   the derived step;
9. retain the derived predecessor reference, step, and reference only as internal
   validated records used to build the selected disclosure;
10. require the final derived chain reference to be byte-identical to the supplied
    `current_chain_ref`.

The anchor MUST NOT be built from a caller-provided list of arbitrary step digests.

## 6. Membership leaf

One leaf binds the one-based handoff index to the exact validated step commitment:

```json
{
  "schema": "ttrace-witness-policy-handoff-chain-membership-leaf/v0.1",
  "handoff_index": 2,
  "step_commitment_sha256": "..."
}
```

The leaf hash is the SHA-256 digest of the canonical JSON object. Index binding
prevents a valid step commitment from being moved to a different position without
changing the root.

## 7. Internal node

An internal node is:

```json
{
  "schema": "ttrace-witness-policy-handoff-chain-membership-node/v0.1",
  "left_sha256": "...",
  "right_sha256": "..."
}
```

Its hash is the SHA-256 digest of the canonical JSON object. Left and right order is
semantic and MUST NOT be normalized or sorted.

## 8. Tree construction

Version 0.1 uses:

```text
pairwise-duplicate-last-sha256/v0.1
```

Rules:

1. leaves are ordered by contiguous `handoff_index`;
2. adjacent hashes are combined left-to-right;
3. when a level has an odd final node, that node is duplicated as its own right
   sibling;
4. levels are repeated until one root remains;
5. tree size is committed separately in both anchor and proof.

The construction is deterministic. Reordering, omitting, or duplicating a handoff
changes the root or fails sequence validation.

## 9. WitnessPolicyHandoffChainMembershipAnchor

The anchor has exactly:

```text
schema
chain_id
policy_id
genesis_policy_epoch
genesis_policy_sha256
completed_handoffs
current_policy_epoch
current_policy_sha256
current_chain_ref_sha256
current_chain_root_sha256
current_step_commitment_sha256
tree_size
tree_algorithm
step_commitment_merkle_root_sha256
chain_contract_sha256
chain_authorization_contract_sha256
membership_contract_sha256
authorization_contract_sha256
```

`schema` MUST equal
`ttrace-witness-policy-handoff-chain-membership-anchor/v0.1` exactly.

The anchor MUST bind the exact validated current chain reference, including:

- chain, policy, and genesis identity;
- completed handoff count and current policy epoch/digest;
- exact current chain-reference digest and rolling chain root;
- exact current/final step commitment;
- the chain contract and chain-authorization contract carried by the current
  chain reference;
- the membership contract and its separate authorization contract;
- tree size, algorithm, and Merkle root.

The invariants include:

```text
tree_size == completed_handoffs
current_policy_epoch == genesis_policy_epoch + completed_handoffs
current_chain_ref_sha256 == sha256(canonical_json(current_chain_ref))
current_chain_root_sha256 == current_chain_ref.chain_root_sha256
current_step_commitment_sha256 == current_chain_ref.step_commitment_sha256
chain_authorization_contract_sha256 ==
    current_chain_ref.authorization_contract_sha256
```

The final step commitment is repeated explicitly. Verification MUST recompute the
final leaf at `handoff_index == tree_size` and verify a separate final-step sibling
path against `step_commitment_merkle_root_sha256`. Tree-size equality alone is not
sufficient: a same-size tree that omits the actual current step MUST be rejected.

`membership_contract_sha256` and `authorization_contract_sha256` identify the
companion membership semantics and authorization plane. They are distinct from
`chain_contract_sha256` and `chain_authorization_contract_sha256`; all four are
bound into the anchor so one plane cannot be substituted for the other.

## 10. Membership proof

A proof has exactly:

```text
schema
anchor_sha256
handoff_index
leaf_index
tree_size
tree_algorithm
step_commitment_sha256
leaf_sha256
sibling_path
current_step_sibling_path
```

`schema` MUST equal
`ttrace-witness-policy-handoff-chain-membership-proof/v0.1` exactly.

The selected handoff uses a one-based `handoff_index`, while `leaf_index` is
zero-based:

```text
leaf_index == handoff_index - 1
```

Each sibling entry has exactly:

```json
{
  "side": "left",
  "sha256": "..."
}
```

`side` is exactly `left` or `right`. Path length is determined by `tree_size`;
missing and extra entries MUST be rejected. At an odd duplicate-last level, the
right sibling MUST equal the current node hash. A verifier MUST reject a substituted
digest even if a later collision-like structure would otherwise produce the claimed
root.

`sibling_path` proves the selected handoff. `current_step_sibling_path`
independently proves the anchor's current step as the final leaf. Both paths are
checked even when the selected handoff is itself the current handoff.

## 11. Selective disclosure package

The top-level object has exactly:

```text
schema
anchor
current_chain_ref
disclosed_handoff
membership_proof
```

Its schema is
`ttrace-witness-policy-handoff-chain-selective-disclosure/v0.1`.

`disclosed_handoff` has exactly:

```text
handoff_index
previous_chain_ref
handoff_package
chain_step
chain_ref
step_commitment_sha256
```

For handoff `1`, `previous_chain_ref` MUST be `null`. For a later handoff it MUST be
the exact, validated fixed-shape predecessor chain reference with
`completed_handoffs == handoff_index - 1`.

The predecessor reference reveals bounded active context, not its predecessor
handoff package or the preceding chain history. It is necessary so a verifier can
rebuild a seed or direct advance rather than trusting a detached step digest.

The selected `handoff_package` is intentionally complete. It includes the old
active quorum, both handoff role certificates and their observations, the new
activation quorum, the handoff statement, the certificate, and all intrinsic
witness/authority evidence required by the predecessor verifier. The package is
independently revalidated.

Accordingly, this profile MUST NOT recursively ban identifiers or evidence fields
that are legitimate members of the selected handoff package. Its privacy boundary
is history-level, not evidence-level.

The disclosure MUST NOT add:

```text
all handoff records
all handoff packages
intermediate handoff packages
intermediate chain steps or references beyond the one direct predecessor
parallel candidate histories
```

Exact outer shapes make such additions fail closed.

## 12. Verification algorithm

A conforming verifier MUST:

1. reject malformed, extended, or excessively nested top-level objects;
2. validate the exact disclosure schema;
3. validate the current chain reference's exact shape and self-bound rolling root;
4. validate the anchor against that exact current chain reference;
5. require `tree_size == completed_handoffs` and the exact tree algorithm;
6. validate the exact proof schema and bind `anchor_sha256` to the canonical anchor;
7. require a strict positive integer `handoff_index`, reject booleans/floats, and
   require `leaf_index == handoff_index - 1`;
8. bind proof index, size, algorithm, and step commitment to the disclosed handoff;
9. independently verify the complete selected dual-quorum handoff package;
10. if `handoff_index == 1`, require a null predecessor and rebuild the seed from
    the anchor's chain ID, genesis policy, chain contract, and chain-authorization
    contract;
11. otherwise validate the exact predecessor chain reference, require its count to
    equal `handoff_index - 1`, require chain/policy/genesis/contract continuity, and
    advance it with the selected handoff package;
12. compare the rebuilt `chain_step` and `chain_ref` with the disclosed objects
    using canonical byte equality;
13. recompute `step_commitment_sha256` from the exact rebuilt step and bind it to the
    rebuilt chain reference and proof;
14. require the selected reference to share the anchor/current tip's chain ID,
    policy ID, genesis policy, chain contract, and authorization contract;
15. when the selected index equals `tree_size`, require the selected chain reference
    to be byte-identical to `current_chain_ref`;
16. recompute the domain-separated selected leaf and validate every path side,
    sibling digest, expected path length, and duplicate-last edge;
17. recompute the final leaf from the anchor's current step commitment at
    `leaf_index == tree_size - 1` and validate `current_step_sibling_path` against
    the same Merkle root;
18. reject full-history material or unknown fields outside the selected handoff
    package.

No receipt boolean, supplied digest, step, or chain reference is trusted without
recomputation or validation at its defined boundary.

## 13. Complexity and disclosure boundary

For `n` handoffs, each sibling path contains approximately:

```text
ceil(log2(n))
```

hashes. The reference disclosure carries two checked paths:

- one for the selected historical handoff;
- one for the current/final step that binds the membership root to the supplied tip.

The total Merkle proof material is therefore still `O(log n)`. The selected handoff
package and one fixed-shape predecessor reference add bounded material independent
of the number of intermediate rotations.

The verifier learns:

- current and selected handoff indexes;
- chain, policy, genesis, current policy, and contract context;
- the complete semantic and witness evidence for the selected rotation;
- one direct predecessor chain reference;
- opaque sibling hashes for undisclosed rotations.

The verifier does not receive the semantic contents, quorum packages, witness
observations, steps, or chain references for the other intervening rotations.

## 14. Fail-closed conditions

The reference verifier rejects at least:

- malformed, extra, or wrong-schema anchor, proof, disclosure, path, or disclosed
  handoff fields;
- recursion or excessive nesting intended to bypass shape checks;
- booleans, floats, zero, negative, or out-of-range indexes and tree sizes;
- an invalid or substituted current chain reference;
- anchor/current-tip disagreement in identity, genesis, count, policy, root, step,
  chain contract, or authorization contract;
- zero Merkle-root, chain-contract, chain-authorization-contract,
  membership-contract, or membership-authorization-contract digests;
- a proof rebound to another anchor;
- a wrong tree size, algorithm, leaf index, or step commitment;
- arbitrary step digests or a retained history that is reordered, incomplete,
  discontinuous, or not current-tip-complete during anchor construction;
- a missing/non-null seed predecessor, or a missing/invalid later predecessor;
- a predecessor with the wrong completed count, chain context, genesis, or
  contracts;
- a selected handoff package that fails the existing direct verifier;
- a supplied step or chain reference that differs from the rebuilt direct result;
- selected package/step/reference/digest substitution;
- a missing, extra, reordered, side-flipped, or modified sibling;
- an invalid odd-level duplicate-last sibling;
- a Merkle-root mismatch;
- a same-size tree that omits the current step;
- a selected final chain reference different from the supplied current reference;
- embedded full history or intermediate handoff packages outside the one selected
  package.

## 15. Assurance boundary

A successful result establishes, relative to the supplied membership anchor and
current chain reference, that:

- the selected complete handoff package passes the existing dual-quorum handoff
  verifier;
- the selected chain step is a valid seed or a valid direct extension of the one
  disclosed predecessor reference;
- the exact selected step commitment is a member of the supplied Merkle root;
- the same Merkle root contains the supplied current chain reference's declared
  final step at the final position;
- disclosure does not reveal hidden intermediate package bodies and grows only
  logarithmically with their count through the two Merkle paths.

Anchor construction in the reference implementation validates the complete retained
chain. A selective verifier, however, does not independently revalidate the semantic
contents of undisclosed leaves. Its structural claim is membership in the supplied
anchor, not an oracle claim about hidden material.

This profile does **not** by itself establish:

- authenticity or authorization of an unsigned/unattested membership anchor;
- freshness or rollback resistance when the relying party did not pin or otherwise
  authenticate the current chain reference;
- append-only consistency between two different membership anchors;
- global non-equivocation or discovery of an undisclosed root, chain fork, or
  successor;
- transparency-log, gossip, or witness-availability completeness;
- cryptographic signature authenticity when the existing external verification
  boundary was skipped;
- witness honesty, independence, key custody, or Byzantine consensus;
- capture completeness;
- validity of undisclosed handoff packages as independently checked by the selective
  verifier;
- zero-knowledge privacy or hiding of tree size, indexes, selected witness evidence,
  or policy context;
- indefinite cryptographic durability.

Deployments SHOULD sign, attest, publish, or otherwise authenticate both the anchor
and the current chain tip when authority, freshness, or non-equivocation is part of
the relying-party claim.

Accordingly, the reference decision reports membership-anchor authorization and
current-tip freshness as `not-evaluated`. A successful local proof check MUST NOT
be relabeled as `pinned-predecessor-handoff-chain-verified` unless a separate
caller-controlled trust process actually authenticates the anchor and pins or
otherwise establishes freshness for the current chain reference.

The conditional status remains:

```text
global_non_equivocation_status = unproven
```

## 16. Reference implementation

- implementation: `ttrace/lineage_witness_handoff_chain_membership.py`
- tests: `tests/test_lineage_witness_handoff_chain_membership.py`
- executable verifier: `scripts/verify_witness_policy_handoff_chain_membership.py`
- predecessor profile: `spec/repeated-witness-policy-handoff-chain-profile-v0.1.md`

## 17. Next falsifiable gate

**Witness-Policy Handoff Membership-Root Consistency v0.1** — can a later
handoff-membership anchor prove it is an append-only extension of an earlier anchor
without replaying every historical handoff and without turning absence of presented
conflict into a claim of global non-equivocation?
