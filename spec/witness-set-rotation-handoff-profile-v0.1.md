# T-Trace Witness-Set Rotation / Quorum-Handoff Portability Profile v0.1

**Status:** Draft profile
**Scope:** rotate one authenticated witness policy to its next epoch without an interval where neither policy protects the accepted lineage view

## 1. Purpose

The Witness-Quorum Anchor profile accepts an exact lineage-anchor statement when an
externally authenticated threshold of witnesses has observed it.

A witness set eventually changes. Keys expire, operators leave, jurisdictions change,
or a larger witness population is required. Simply replacing
`witness_policy_sha256` creates an anti-equivocation gap:

```text
old policy no longer authoritative
+
new policy not yet linked to the old accepted view
=
unprotected acceptance interval
```

This profile introduces an explicit dual-quorum handoff. One exact producer statement
and one exact lineage view are simultaneously:

1. already accepted by an old-policy active quorum;
2. observed by an old-policy handoff quorum;
3. observed by a new-policy handoff quorum;
4. accepted by a new-policy activation quorum.

## 2. Fractal Causal Refactoring diagnosis

The visible failure is policy-digest drift. Allowing the existing same-policy verifier
to ignore that drift would weaken the policy boundary.

The First Meaningful Divergence occurs in the acceptance topology:

```text
intended rotation
old accepted view
      ↓ old quorum authorizes exact transition
exact dual-policy handoff statement
      ↓ new quorum accepts the same view
new accepted view

unsafe shortcut
old policy digest → replaced by new policy digest
```

The repair is therefore a new handoff primitive, not a relaxed comparison rule.

## 3. Layering

```text
Portable Causality
        ↓
Repeated Lineage Compaction
        ↓
Lineage Membership / Selective Disclosure
        ↓
Membership-Root Consistency
        ↓
Witness-Quorum Conditional Non-Equivocation
        ↓
Witness-Set Rotation / Quorum Handoff
```

The base T-Trace record, membership root, accumulator, producer statement, and normal
quorum package remain unchanged.

## 4. Policy transition

A v0.1 handoff rotates one policy lineage by exactly one epoch.

Requirements:

- both old and new policies independently satisfy the Witness-Quorum profile;
- `old.policy_id == new.policy_id`;
- `new.policy_epoch == old.policy_epoch + 1` using strict JSON integer semantics;
- old and new canonical policy digests differ;
- contract changes are explicit because the complete policies are digest-bound;
- skipped epochs and opaque policy replacement fail closed.

The old and new witness sets may partially overlap or be disjoint. Cross-policy witness
overlap is useful operationally but is not required for correctness. The exact same
handoff statement must receive valid quorums under both policies.

## 5. Exact handoff statement

`LineageWitnessPolicyHandoffStatement` binds:

- the externally verified producer authority;
- the exact producer anchor statement;
- trust domain and logical state;
- tree size, anchor, and membership root;
- policy identity;
- old and new policy digests and epochs;
- handoff contract and authorization contract;
- external handoff provenance.

Example shape:

```json
{
  "schema": "ttrace-lineage-witness-policy-handoff-statement/v0.1",
  "verified": true,
  "authority_id": "ed25519-sha256:producer",
  "trust_domain": "example.procurement",
  "logical_state_id": "authorization-state",
  "tree_size": 9,
  "anchor_sha256": "...",
  "membership_root_sha256": "...",
  "producer_statement_sha256": "...",
  "policy_id": "lineage-witness-set",
  "old_policy_sha256": "...",
  "new_policy_sha256": "...",
  "old_policy_epoch": 1,
  "new_policy_epoch": 2,
  "handoff_contract_sha256": "...",
  "authorization_contract_sha256": "...",
  "handoff_provenance_sha256": "..."
}
```

`verified = true` is a normalization boundary. T-Trace core does not treat a caller
boolean as a signature.

## 6. Handoff observation

A handoff observation binds one witness to the exact handoff statement and therefore
to:

```text
producer statement
+
old policy
+
new policy
+
handoff contracts
```

One observation may count in both role certificates when the witness belongs to both
policies. The observation is still stored once and appears once in the canonical
observation list.

Sequence rules are global to the supplied witness history:

- a first observation uses sequence `1` and the all-zero predecessor;
- a later observation requires a non-zero predecessor;
- continuity edges are verified separately against the old active and new activation
  packages.

## 7. Four acceptance stages

A complete package contains:

```text
old active quorum package
old handoff quorum certificate
new handoff quorum certificate
new activation quorum package
```

All four stages bind the same producer statement and lineage view.

### 7.1 Old continuity edge

The old active quorum and old handoff quorum are both valid under the same old policy.
Their actual witness overlap must be at least:

```text
2 × old_threshold − old_authorized_witness_count
```

Every overlapping witness must advance exactly one sequence and bind the digest of
its exact old active observation.

### 7.2 New continuity edge

The new handoff quorum and new activation quorum are both valid under the same new
policy. Their actual overlap must satisfy the analogous new-policy minimum.

Every overlapping witness in the activation package must advance exactly one sequence
and bind the digest of its exact handoff observation.

### 7.3 Cross-policy overlap

The receipt reports witnesses that belong to both handoff role certificates. This is
informational and strengthens operational continuity, but the count may be zero.

The no-gap claim comes from dual authorization of the exact same handoff statement,
plus independently verified continuity on both policy sides.

## 8. Handoff certificate

The portable handoff certificate commits:

- the exact handoff statement;
- producer statement and lineage context;
- old and new policy digests and epochs;
- old active, old handoff, new handoff, and new activation certificate digests;
- minimum old and new quorum intersections;
- exact old-side and new-side continuity witness IDs;
- cross-policy handoff witness IDs;
- handoff contracts;
- explicit no-gap and assurance statuses.

The certificate uses exact schemas and canonical witness ordering. Unknown fields,
reordering, duplicate witnesses, or recomputation mismatches fail closed.

## 9. Canonical three-of-five example

```text
old policy: w1,w2,w3,w4,w5  threshold 3
new policy: w4,w5,w6,w7,w8  threshold 3

old active quorum:      w1,w2,w3
old handoff quorum:     w3,w4,w5
new handoff quorum:     w4,w5,w6
new activation quorum:  w6,w7,w8

old continuity overlap: w3
new continuity overlap: w6
cross-policy overlap:   w4,w5
```

Both policy-side minimum intersections are `1`.

## 10. Conflicting handoffs

Two valid handoff packages are comparable for rotation conflict when they share:

- the exact old policy;
- the exact old producer statement and accepted lineage view.

They conflict when they authorize different new policy digests or different handoff
contract semantics.

Because both old handoff certificates are valid quorums under the same intersecting
old policy, they necessarily share at least the old-policy minimum number of
witnesses. The detector emits the two exact handoff-observation digests for every
supplied overlapping old witness.

This is attributable supplied-view evidence. It does not prove motive, key custody,
or global behavior outside the supplied packages.

## 11. Fail-closed conditions

The reference implementation rejects at least:

- malformed or extended statement, observation, role certificate, package, receipt,
  or conflict-evidence shapes;
- boolean epochs, thresholds, or observation sequences;
- invalid old or new policy;
- policy-ID drift, epoch skipping, or identical old/new policy bytes;
- old/new active packages bound to different producer statements or lineage views;
- handoff-statement rebinding;
- unauthorized, duplicate, unsorted, missing, insufficient, or certificate-uncovered handoff observations;
- role certificate recomputation mismatch;
- insufficient old-side or new-side continuity overlap;
- old handoff sequence or predecessor discontinuity;
- new activation sequence or predecessor discontinuity;
- receipt recomputation mismatch;
- conflict comparison across different old-policy or producer-statement contexts.

## 12. Assurance boundary

A successful v0.1 handoff establishes for the supplied externally verified evidence:

- one exact accepted lineage view under the old policy;
- an old-policy quorum authorizing one exact next policy;
- a new-policy quorum accepting the same exact handoff statement;
- one exact accepted activation view under the new policy;
- direct witness continuity on both policy sides;
- no unprotected acceptance gap inside the supplied four-stage handoff;
- attributable old-policy double-signing when conflicting handoffs are supplied.

It does not by itself establish:

- cryptographic authenticity when external verification was skipped;
- witness honesty, independence, availability, or key security;
- global non-equivocation;
- Byzantine consensus;
- gossip or transparency-log completeness;
- capture completeness;
- multi-epoch or rollback-safe policy rotation beyond one direct handoff;
- safe emergency recovery when either quorum is unavailable;
- zero knowledge.

Every decision retains:

```text
conditional_handoff_status = "dual-quorum-handoff-verified"
conditional_non_equivocation_status =
  "supported-under-witness-quorum-assumptions"
global_non_equivocation_status = "unproven"
```

## 13. Complexity and disclosure

For old/new quorum sizes `q_old` and `q_new` and `h` unique handoff observations:

- package verification is `O(q_old + q_new + h)`;
- continuity checks are linear in the actual policy-side overlaps;
- conflict comparison is linear in the old handoff quorum sizes;
- witness IDs and observation digests are intentionally disclosed for accountability;
- no raw lineage cycle records are required beyond the existing compact endpoint
  material.

## 14. Reference implementation

- implementation: `ttrace/lineage_witness_handoff.py`
- tests: `tests/test_lineage_witness_handoff.py`
- executable verifier: `scripts/verify_witness_policy_handoff.py`
- predecessor profile: `spec/witness-quorum-anti-equivocation-profile-v0.1.md`

## 15. Next falsifiable gate

**Repeated Witness-Policy Rotation / Handoff-Chain Consistency v0.1** — prove multiple
successive policy rotations with explicit rollback resistance and bounded active
handoff state, without requiring every historical quorum package in memory.
