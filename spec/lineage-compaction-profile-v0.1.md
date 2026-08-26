# T-Trace Repeated Fork / Reconciliation Lineage Compaction v0.1

**Status:** Draft profile  
**Scope:** bounded active lineage commitments after repeated portable fork and reconciliation cycles

## 1. Purpose

The Portable Causality Profile defines a canonical two-parent reconciliation. A
long-running system may perform that operation repeatedly:

```text
state 0
  ├─ branch A ─┐
  └─ branch B ─┴─ reconciled state 1
                         ├─ branch C ─┐
                         └─ branch D ─┴─ reconciled state 2
```

Embedding every prior branch, vote, parent set, and receipt into every new active
state would cause the operational object to grow with history.

This profile defines a fixed-shape `LineageAccumulatorRef` that commits prior
verified cycles while keeping full proof material external and independently
retained.

The central rule is:

> **Active causal identity and complete audit ancestry are different objects.**

Compaction MUST NOT mean deleting history. It means replacing raw ancestry in the
active tip with a rolling cryptographic commitment to that ancestry.

## 2. Relationship to existing profiles

```text
T-Trace v0.1 record envelope
        ↓
Causal Execution Graph Profile
        ↓
Portable Causality Profile
        ↓
Lineage Compaction Profile
```

This profile does not change the base JSONL envelope and does not replace the
Portable Causality verifier. Every newly compacted cycle MUST first pass the full
two-parent reconciliation rules.

## 3. LineageAccumulatorRef

A v0.1 accumulator has an exact, fixed set of 13 fields:

```json
{
  "schema": "ttrace-lineage-accumulator-ref/v0.1",
  "trust_domain": "example.procurement",
  "logical_state_id": "authorization-state",
  "completed_reconciliation_cycles": 2,
  "current_causal_epoch": 4,
  "current_state_ref_sha256": "...",
  "current_reconciliation_sha256": "...",
  "previous_accumulator_sha256": "...",
  "previous_lineage_root_sha256": "...",
  "cycle_commitment_sha256": "...",
  "lineage_root_sha256": "...",
  "accumulator_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

The field set MUST remain unchanged as the number of cycles increases.

### 3.1 Semantic identity

- `trust_domain` identifies the namespace in which the state has meaning.
- `logical_state_id` identifies the continuing state machine.
- `completed_reconciliation_cycles` counts compacted reconciliations.
- `current_causal_epoch` is the epoch of the current reconciled `StateRef`.

### 3.2 Current active tip

- `current_state_ref_sha256` binds the current reconciled state.
- `current_reconciliation_sha256` binds the complete current portable
  reconciliation agreement.

### 3.3 Previous lineage

- `previous_accumulator_sha256` binds the complete previous accumulator object.
- `previous_lineage_root_sha256` binds its rolling root.

For cycle 1 both fields MUST be the all-zero SHA-256 value. For later cycles both
MUST be non-zero.

### 3.4 Current cycle

`cycle_commitment_sha256` commits a canonical cycle summary containing:

- cycle index;
- exact common state;
- fork and reconciliation epochs;
- canonical branch-tip set;
- canonical parent set;
- reconciliation reference;
- result state;
- reconciliation receipt;
- reconciliation and authorization contracts.

### 3.5 Policy bindings

- `accumulator_contract_sha256` identifies the compaction rules.
- `authorization_contract_sha256` identifies the authorization rules for
  advancing the accumulator.

## 4. Rolling root equation

The lineage root is computed over every non-root accumulator field:

```text
lineage_root[n] = SHA-256(canonical JSON {
  schema,
  trust_domain,
  logical_state_id,
  completed_reconciliation_cycles,
  current_causal_epoch,
  current_state_ref_sha256,
  current_reconciliation_sha256,
  previous_accumulator_sha256,
  previous_lineage_root_sha256,
  cycle_commitment_sha256,
  accumulator_contract_sha256,
  authorization_contract_sha256
})
```

A verifier MUST recompute this equation. It MUST reject a value when any field is
changed without a corresponding root change.

A root is a commitment, not an authorization signature. Deployments that require
cryptographic authority MUST authenticate the accumulator or the record carrying
it through a separate signature, attestation, or receipt profile.

## 5. Seed construction

The first verified two-parent reconciliation MAY be compacted into a seed:

```text
previous_accumulator_sha256 = 00...00
previous_lineage_root_sha256 = 00...00
completed_reconciliation_cycles = 1
```

Before producing the seed, a verifier MUST fully validate the reconciliation
against its exact common state.

## 6. Incremental advancement

To advance from cycle `n` to `n + 1`, a verifier MUST:

1. validate the exact shape and root of accumulator `n`;
2. require its `current_state_ref_sha256` to equal the supplied common state;
3. require the trust domain and logical state identity to match;
4. validate two new independent, semantically divergent branches;
5. validate two branch-bound reconciliation votes;
6. build and validate the new canonical reconciliation;
7. commit the new cycle summary;
8. bind accumulator `n` and root `n` into accumulator `n + 1`;
9. recompute the complete accumulator and receipt bytes.

The new accumulator MUST preserve the same field set.

## 7. Compaction receipt

A verified receipt binds:

- previous and completed cycle counts;
- common, fork, and reconciled epochs;
- previous accumulator and root;
- current cycle commitment and lineage root;
- current accumulator, state, and reconciliation;
- accumulator field count;
- shape stability;
- preservation of both current lineages;
- absence of embedded raw ancestry and provider evidence.

The receipt key set is exact. Unknown fields MUST be rejected by the reference
validator.

## 8. External proof retention

The accumulator does not contain enough information to reconstruct all prior
branches. Full proof packages SHOULD retain:

- every compacted reconciliation agreement;
- provider-bound branch evidence and votes;
- signatures or attestations;
- prior accumulators and receipts;
- referenced policy and contract material.

A verifier checking the complete historical chain follows the
`previous_accumulator_sha256` links back to a trusted seed.

A verifier accepting only the latest accumulator verifies a commitment to prior
history, not the content or membership of every historical branch.

## 9. Fail-closed requirements

The reference implementation rejects at least:

- malformed or extended accumulator shapes;
- invalid root equations;
- zero current-state, current-reconciliation, cycle, root, or contract digests;
- a seed that claims a non-zero predecessor;
- a later cycle that drops its predecessor;
- mismatch between the previous active state and the next common state;
- trust-domain or logical-state discontinuity;
- non-divergent branches;
- branch or authorization contract disagreement;
- votes bound to another branch or target;
- altered compaction receipt fields;
- raw provider, authority, or provenance identities embedded in portable output.

## 10. Mapping to T-Trace records

A profile-aware implementation SHOULD carry the accumulator in the payload of the
`commit` record that represents a reconciliation. The commit SHOULD reference the
full proof package through `evidence_refs` or an equivalent stable digest.

The next fork uses the reconciled `StateRef` as its common state and the previous
accumulator as its bounded lineage commitment.

## 11. Assurance boundary

This profile establishes for supplied material:

- repeated two-parent reconciliation;
- constant accumulator field count;
- rolling commitment to every previous accumulator and root;
- binding of the current state and reconciliation;
- provider-free active lineage identity;
- fail-closed detection of field tampering.

It does **not** by itself establish:

- capture completeness;
- correctness of the reconciliation policy;
- authenticity of an unsigned accumulator;
- Byzantine quorum correctness;
- arbitrary N-parent reconciliation;
- selective membership proof for a hidden historical cycle;
- deletion resistance of external proof storage;
- indefinite durability.

## 12. Reference implementation

- implementation: `ttrace/lineage_compaction.py`
- executable verifier: `scripts/verify_lineage_compaction.py`
- regression tests: `tests/test_lineage_compaction.py`

## 13. Next falsifiable question

**Lineage Membership / Selective Historical Disclosure v0.1**

Can a prover demonstrate that one selected historical fork belongs to the current
lineage commitment without disclosing every intervening branch and reconciliation?
