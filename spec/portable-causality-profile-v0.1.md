# T-Trace Portable Causality Profile v0.1

**Status:** Draft profile
**Scope:** canonical semantic state identity, causal transitions, forks, and two-parent reconciliation for T-Trace payloads

## 1. Purpose

T-Trace v0.1 records acknowledged state transitions in an append-only JSONL stream. This optional profile defines a portable identity layer for systems where the same logical state may be established by different evidence providers or historical paths.

The central rule is:

> **Evidence proves a causal state; evidence does not become the causal state's portable identity.**

The profile also makes reconciliation explicit:

> **A reconciliation is a DAG join that commits every authorizing parent, not a relaxed linear transition that selects one predecessor.**

## 2. Relationship to T-Trace v0.1

This profile does not change the base record envelope:

```text
id
type
ts
thread_id
```

Profile objects are carried as additional domain payload fields. The existing base validator remains unchanged.

The base trace may serialize records linearly, but profile-level causal order is established by explicit references and canonical digests. Wall-clock timestamps remain descriptive and MUST NOT replace declared causal lineage in distributed workflows.

## 3. Canonical serialization

Portable profile objects MUST be serialized as UTF-8 JSON with:

- object keys sorted lexicographically;
- no insignificant whitespace;
- separators `,` and `:`;
- non-ASCII characters encoded directly;
- non-finite numbers rejected.

Object identity is:

```text
sha256(canonical_json_bytes(object))
```

All digest fields in this profile use lowercase, 64-character hexadecimal SHA-256 values.

## 4. Portable state identity

A `StateRef` identifies what the system currently means, independently of the evidence path that established it.

```json
{
  "schema": "ttrace-portable-state-ref/v0.1",
  "trust_domain": "example.procurement",
  "logical_state_id": "authorization-state",
  "causal_epoch": 2,
  "semantic_state_sha256": "..."
}
```

Required fields:

- `trust_domain` — namespace in which the state has meaning;
- `logical_state_id` — stable identity of the logical state machine;
- `causal_epoch` — portable causal position;
- `semantic_state_sha256` — digest of the canonical semantic state.

A provider ID, signer identity, registry digest, manifest digest, storage location, workflow run, or historical generation MUST NOT be embedded in `StateRef` merely because it supplied evidence for the state.

## 5. Portable transition identity

A `TransitionRef` binds one semantic state reference to the next.

```json
{
  "schema": "ttrace-portable-transition-ref/v0.1",
  "trust_domain": "example.procurement",
  "logical_state_id": "authorization-state",
  "logical_transition_id": "policy-update",
  "from_causal_epoch": 2,
  "to_causal_epoch": 3,
  "from_state_ref_sha256": "...",
  "to_state_ref_sha256": "...",
  "transition_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

A causal transition MUST:

1. bind the exact predecessor `StateRef`;
2. advance `causal_epoch` by exactly one;
3. produce a different semantic-state digest;
4. bind the transition and authorization contracts.

A history-only no-op MAY exist in evidence, but it MUST NOT advance the portable causal epoch.

## 6. Provider-bound branch evidence

Evidence providers authorize portable objects through external evidence. The reference implementation accepts a normalized `BranchEvidence` observation containing:

- verification verdict;
- provider ID;
- authority ID;
- provenance digest;
- trust domain;
- logical branch ID;
- exact common-state reference digest;
- target semantic-state digest;
- branch contract digest;
- authorization contract digest.

Provider, authority, and provenance identities are evidence metadata. They MUST be verified but MUST NOT appear in the resulting portable branch object.

This profile does not prescribe a signature scheme. GitHub OIDC attestations, detached Ed25519 signatures, hardware attestations, or another mechanism MAY establish the normalized evidence observation.

## 7. Fork branch reference and tip

A `ForkBranchRef` binds an exact common state to one divergent semantic state:

```text
common StateRef
    ↓
logical branch + contracts
    ↓
branch StateRef

    ↓ state ref
    ↓ branch ref
    ↓ branch tip
```

The portable branch tip contains only:

```json
{
  "schema": "ttrace-portable-fork-branch-tip/v0.1",
  "state_ref": { "...": "..." },
  "branch_ref": { "...": "..." }
}
```

The portable branch tip excludes raw provider, authority, and provenance fields.

## 8. Genuine fork requirements

Version 0.1 supports exactly two branches.

A verifier MUST reject the fork unless:

1. both branch observations are verified;
2. both bind the exact same common `StateRef`;
3. provider IDs are distinct;
4. authority IDs are distinct;
5. provenance digests are distinct;
6. logical branch IDs are distinct;
7. branch and authorization contracts agree;
8. each branch advances exactly one causal epoch;
9. the two branch semantic-state digests are different.

Two providers reproducing one semantic state are convergence, not a fork.

## 9. Reconciliation votes

Each branch authority supplies a vote bound to its exact portable branch tip.

A normalized vote binds:

- provider and authority identity;
- vote provenance digest;
- logical reconciliation ID;
- branch-ref digest;
- branch-state-ref digest;
- branch-tip digest;
- target semantic-state digest;
- reconciliation contract digest;
- reconciliation authorization digest.

A verifier MUST reject a vote that is valid in isolation but bound to a different branch tip.

Both votes MUST agree on:

- logical reconciliation ID;
- target semantic state;
- reconciliation contract;
- authorization contract;
- trust domain.

The reconciled target MUST be distinct from the common state and both divergent branch states.

## 10. Canonical two-parent reconciliation

The parent set contains both branch tips in deterministic digest order.

```json
{
  "schema": "ttrace-portable-causal-parent-set/v0.1",
  "parents": [
    {
      "branch_tip_sha256": "...",
      "branch_ref_sha256": "...",
      "state_ref_sha256": "..."
    },
    {
      "branch_tip_sha256": "...",
      "branch_ref_sha256": "...",
      "state_ref_sha256": "..."
    }
  ]
}
```

The parent entries MUST be sorted by `branch_tip_sha256`.

A `ReconciliationRef` binds:

- the exact common state;
- fork and reconciliation causal epochs;
- the canonical parent set;
- both branch-tip digests;
- the reconciled `StateRef`;
- reconciliation and authorization contracts.

Reversing branch input order MUST produce byte-identical portable parent-set, reconciliation-reference, and receipt objects.

A verifier MUST reject reconciliation with a missing, duplicated, or replaced parent.

## 11. Receipt

A verified v0.1 receipt reports at least:

```text
lineage_parent_count       = 2
both_lineages_preserved    = true
fork_semantics_divergent   = true
branch_order_canonical     = true
raw_evidence_embedded      = false
```

The receipt also binds the common state, parent set, reconciled state, and reconciliation reference by digest.

## 12. Mapping to T-Trace records

A profile-aware implementation SHOULD represent each branch as a `transition` record whose domain payload includes its portable branch tip and whose causal parent references the exact common record.

A reconciliation SHOULD be represented as a `commit` record that:

- names both branch records as material causal parents;
- carries the `ReconciliationRef`;
- carries or references the verification receipt;
- does not erase either branch lineage.

A linear JSONL presentation order MUST NOT imply that one branch causally precedes the other.

## 13. Fail-closed conditions

The reference verifier rejects at least:

- malformed state or digest material;
- unverified branch evidence or votes;
- non-independent provider, authority, or provenance evidence;
- duplicate logical branch identity;
- branch contract or authorization disagreement;
- a branch not bound to the exact common state;
- non-divergent fork semantics;
- a vote bound to the wrong branch ref, state ref, or tip;
- vote target, contract, authorization, or trust-domain disagreement;
- a target that simply repeats common or branch state;
- missing or duplicated reconciliation parents;
- raw evidence identity embedded in portable output;
- non-canonical input ordering that changes portable bytes.

## 14. Assurance boundary

This profile proves structural and semantic consistency of the supplied portable objects and normalized evidence observations.

It does **not** by itself prove:

- that every real-world effect was captured;
- that the evidence provider was uncompromised;
- cryptographic completeness or selective-deletion resistance;
- correctness of the domain policy that selected the reconciled state;
- Byzantine quorum correctness;
- transport, storage, hardware, or organizational independence;
- arbitrary N-parent or indefinitely repeated reconciliation.

These concerns require separate profiles, evidence, or system controls.

## 15. Reference implementation

- implementation: `ttrace/portable_causality.py`
- verifier: `scripts/verify_portable_causality.py`
- tests: `tests/test_portable_causality.py`
- canonical example: `examples/causal-portability/fork-reconciliation.json`
- research provenance: `docs/liminal-research-provenance.md`

The base `scripts/validate_ttrace.py` behavior is intentionally unchanged.
