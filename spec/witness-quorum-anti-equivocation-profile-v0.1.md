# T-Trace Witness-Quorum Anchor / Conditional Non-Equivocation Profile v0.1

**Status:** Draft profile  
**Scope:** threshold witness acceptance for lineage-anchor statements and attributable split-view evidence inside one authenticated witness policy

## 1. Purpose

The Membership-Root Consistency profile proves that one supplied membership root is
an append-only extension of another and can attribute a conflict when two producer
statements are explicitly compared.

That profile deliberately reports:

```text
global_non_equivocation_status = "unproven"
```

because one producer can show different statements to parties that never compare
views.

This profile adds a shared-observation layer. A lineage-anchor statement is accepted
only when an externally authenticated threshold of authorized witnesses has observed
and signed or attested that exact statement.

The central distinction is:

> **A root is structural state. A quorum certificate is acceptance evidence.**

The profile does not change the membership root, membership tree, accumulator, or
portable causal-state identity.

## 2. Fractal Causal Refactoring diagnosis

The visible failure is a split-view producer:

```text
relying party A ← producer statement X
relying party B ← producer statement Y
```

Adding more pairwise comparisons does not repair the earliest divergence. The first
meaningful divergence occurs before acceptance:

```text
intended system
producer statement → shared observation → accepted root

old acceptance boundary
producer statement → accepted root
```

The repair therefore belongs in the acceptance layer, not in the Merkle-root
algorithm.

## 3. Layering

```text
Portable Causality
        ↓
Repeated Lineage Compaction
        ↓
Lineage Membership / Selective Disclosure
        ↓
Membership-Root Consistency / Presented-View Equivocation
        ↓
Witness-Quorum Anchor / Conditional Non-Equivocation
```

The base T-Trace v0.1 record envelope remains unchanged.

## 4. External verification boundary

`verified = true` in a witness observation means an external signature,
attestation, or equivalent verifier has already authenticated the witness evidence.

T-Trace core does not turn a caller-provided boolean into a signature.

A production deployment MUST authenticate:

- the witness policy;
- every witness identity;
- every witness observation;
- the producer anchor statement;
- any policy rotation.

## 5. Witness policy

A v0.1 policy has exactly:

```json
{
  "schema": "ttrace-lineage-witness-policy/v0.1",
  "policy_id": "lineage-witness-set-1",
  "policy_epoch": 1,
  "authorized_witness_ids": ["w1", "w2", "w3", "w4", "w5"],
  "threshold": 3,
  "witness_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

Requirements:

- witness identifiers are non-empty, unique, and lexicographically sorted;
- `policy_epoch` and `threshold` use strict JSON integer semantics; Python booleans
  are rejected;
- contract digests are non-zero lowercase SHA-256 values;
- `threshold <= authorized_witness_count`;
- v0.1 requires strict quorum intersection:

```text
2 × threshold > authorized_witness_count
```

The guaranteed minimum intersection is:

```text
2 × threshold − authorized_witness_count
```

For a three-of-five policy, every pair of valid quorums shares at least one witness.

## 6. Witness observation

A normalized witness observation binds one exact producer statement and its complete
membership context:

```json
{
  "schema": "ttrace-lineage-witness-observation/v0.1",
  "verified": true,
  "witness_id": "w3",
  "witness_sequence": 2,
  "previous_observation_sha256": "...",
  "observation_provenance_sha256": "...",
  "witness_policy_sha256": "...",
  "producer_statement_sha256": "...",
  "authority_id": "ed25519-sha256:producer",
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

Sequence rules:

- a witness's first observation uses sequence `1` and the all-zero predecessor;
- later observations require a non-zero predecessor digest;
- direct witnessed consistency requires every witness appearing in both endpoint
  quorums to advance by exactly one and bind the exact previous observation digest.

A new witness may join a later quorum at its own sequence `1` when the policy already
authorizes that witness.

## 7. Quorum certificate

A certificate commits the exact statement, policy, canonical witness-ID list, and
aligned observation-digest list.

The certificate reports:

- producer authority and statement sequence;
- complete membership comparison context;
- policy digest;
- threshold and authorized witness count;
- guaranteed minimum quorum intersection;
- actual witness count;
- canonical witness identifiers;
- exact observation digests.

Witness observations are sorted by `witness_id`. Reordering observations or adding an
unknown field changes or invalidates the certificate.

## 8. Quorum package

A standalone package contains exactly:

```text
membership anchor
current accumulator
producer anchor statement
witness policy
witness observations
quorum certificate
```

The standalone verifier independently:

1. validates the membership anchor, accumulator, and producer statement;
2. validates the exact witness policy;
3. validates each observation's statement and policy bindings;
4. rejects duplicate, unauthorized, malformed, or unsorted witnesses;
5. requires at least the configured threshold;
6. recomputes the exact certificate bytes.

## 9. Witnessed append-only consistency

A witnessed transition verifies:

```text
old membership endpoint
        ↓ append-only consistency
new membership endpoint

old producer statement
        ↓ direct producer statement chain
new producer statement

old witness quorum
        ↓ intersecting witness chains
new witness quorum
```

Requirements:

- both quorum packages independently validate;
- producer statements pass the existing authorized root-consistency verifier;
- witness-policy digests are identical in v0.1;
- actual witness overlap is at least the policy's minimum intersection;
- every overlapping witness advances by exactly one sequence position;
- every overlapping witness binds the exact prior observation digest.

Policy rotation is outside v0.1 and MUST NOT be represented as an ordinary
continuation.

## 10. Conditional non-equivocation meaning

A successful witnessed transition reports:

```text
conditional_non_equivocation_status =
  "supported-under-witness-quorum-assumptions"
```

This means the supplied certificates satisfy a threshold policy with guaranteed
intersection and the overlapping witness chains are continuous.

The claim is conditional on:

- authentic witness-policy distribution;
- correct external signature or attestation verification;
- at least one honest, non-double-signing witness in every quorum intersection;
- availability or comparison of conflicting certificates;
- witness identity keys not being compromised.

It is not a global theorem about all possible views.

## 11. Attributable witness double-signing

When two valid quorum packages contain conflicting producer statements in the same
membership context, the verifier:

1. invokes the existing producer-equivocation detector;
2. computes the exact overlap of witness IDs;
3. requires the overlap to satisfy the policy minimum;
4. records both observation digests for every overlapping witness;
5. emits attributable witness-equivocation evidence.

With a strict-intersection policy, two valid conflicting certificates necessarily
share at least one witness. An overlapping witness that authenticated both exact
conflicting statements has double-signed within the supplied evidence.

## 12. What this improves

Compared with producer-only statements, a relying party can require:

```text
one authenticated producer statement
+
one authenticated intersecting witness quorum
```

Conflicting accepted certificates become accountable to both:

- the producer authority that issued conflicting anchor statements;
- the overlapping witnesses that authenticated both views.

## 13. Fail-closed conditions

The reference implementation rejects at least:

- malformed policy, observation, certificate, or package shapes;
- unknown fields;
- boolean policy epochs or thresholds;
- unsorted or duplicate authorized witnesses;
- thresholds that do not guarantee intersection;
- zero or malformed contract/provenance digests;
- unauthorized, duplicate, unsorted, or insufficient observations;
- observation-to-policy or observation-to-statement mismatch;
- certificate recomputation mismatch;
- producer root-consistency or statement-chain failure;
- witness-policy drift across a direct transition;
- insufficient actual witness overlap;
- overlapping witness sequence gaps or predecessor mismatch;
- conflict comparison across different witness-policy contexts.

## 14. Complexity and disclosure

For a policy with `n` authorized witnesses and an actual quorum of `q` witnesses:

- package verification is `O(q)`;
- certificate comparison is `O(q log q)` due to canonical ordering;
- overlap comparison is `O(q)` using witness-ID maps;
- no raw lineage cycle records are required beyond the underlying compact consistency
  proof.

Witness IDs and observation digests are intentionally disclosed for accountability.
This profile is not zero knowledge.

## 15. Assurance boundary

This profile establishes for supplied valid evidence:

- threshold witness acceptance of exact lineage-anchor statements;
- guaranteed quorum intersection under one authenticated policy;
- direct continuity for witnesses appearing in both endpoint quorums;
- attributable witness double-signing when conflicting quorum certificates are
  supplied;
- continued structural append-only membership-root consistency.

It does not by itself establish:

- cryptographic authenticity when external verification was skipped;
- global non-equivocation across unobserved certificates;
- witness honesty, independence, availability, or key security;
- Byzantine safety beyond the stated intersection/honesty assumptions;
- policy-rotation safety;
- transparency-log inclusion;
- gossip completeness;
- capture completeness;
- zero-knowledge privacy.

Accordingly every decision retains:

```text
global_non_equivocation_status = "unproven"
```

## 16. Reference implementation

- implementation: `ttrace/lineage_witness.py`
- tests: `tests/test_lineage_witness.py`
- executable verifier: `scripts/verify_lineage_witness_quorum.py`
- predecessor profile: `spec/membership-root-consistency-profile-v0.1.md`

## 17. Next falsifiable gate

**Witness-Set Rotation / Quorum-Handoff Portability v0.1** — rotate the authenticated
witness policy without creating a gap where neither old nor new intersection
assumptions protect the accepted lineage view.
