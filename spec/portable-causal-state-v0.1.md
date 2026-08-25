# T-Trace Portable Causal State Profile v0.1

**Status:** Draft normative profile  
**Relationship:** Extension of T-Trace v0.1 and the Causal Execution Graph Profile  
**Scope:** History-independent identity for semantic state across independently verified implementations and evidence paths

## 1. Purpose

T-Trace v0.1 records acknowledged transitions. The Causal Execution Graph Profile adds explicit causal ordering for distributed execution. This profile defines the identity used when more than one valid history, provider, signer, or representation can establish the same current semantic state.

The central rule is:

> **Provenance proves a semantic state; provenance does not automatically become that state's portable identity.**

A verifier MAY retain provider, signer, registry, manifest, storage, or workflow identities as evidence. It MUST NOT place those identities inside the portable state identity unless the active domain contract explicitly declares them to be part of the state semantics.

## 2. `CausalStateRef`

A portable state reference contains exactly:

```json
{
  "schema": "ttrace-causal-state-ref/v0.1",
  "trust_domain": "ttrace.authorization",
  "logical_state_id": "purchase-42",
  "causal_epoch": 3,
  "semantic_state_sha256": "<64 lowercase hex characters>"
}
```

### 2.1 Fields

- `trust_domain` identifies the semantic verification domain.
- `logical_state_id` identifies the long-lived logical state machine or operation.
- `causal_epoch` identifies the position in the portable causal process.
- `semantic_state_sha256` commits to canonical semantic state.

### 2.2 Excluded by default

The following are provenance by default and MUST NOT be inserted into `CausalStateRef` merely because they were used to prove the state:

- provider or execution environment;
- signer or trust-root identity;
- registry, manifest, log, artifact, or storage digest;
- workflow commit or CI run identity;
- historical generation number;
- transport or network path.

Profiles MAY retain those values in a separate evidence envelope.

## 3. Causal epoch

`causal_epoch` is not a history length or version counter.

```text
historical generation = how one evidence path arrived
causal epoch          = where the portable semantic process is
```

A historical no-op MAY advance a registry or manifest generation without advancing `causal_epoch`.

A causal epoch MUST advance by exactly one when a portable transition produces a different semantic state.

## 4. Canonical semantic state

The profile uses SHA-256 over deterministic UTF-8 JSON:

- object keys sorted lexicographically;
- no insignificant whitespace;
- arrays preserve declared order;
- floating-point values are excluded from the reference canonical subset;
- strings are encoded as UTF-8;
- booleans, integers, strings, null, arrays, and string-keyed objects are supported.

A domain profile MUST define the semantic state object being hashed. Two verifiers MUST NOT claim state equality merely because two arbitrary files have the same business label.

## 5. Validation requirements

A conforming verifier MUST reject a state reference when:

1. the schema is unknown;
2. required fields are missing or extra fields are present;
3. `trust_domain` or `logical_state_id` is empty;
4. `causal_epoch` is negative, non-integral, or boolean;
5. `semantic_state_sha256` is not exactly 64 lowercase hexadecimal characters;
6. the retained evidence does not independently establish the committed semantic state.

## 6. Relationship to evidence

A complete verification bundle SHOULD contain both:

```text
portable identity
+ independently inspectable evidence
```

The portable identity allows equivalent systems to converge. The evidence explains why a verifier accepted it.

Removing evidence from portable identity does not remove the obligation to retain, authenticate, and audit that evidence.

## 7. Claim boundary

This profile defines deterministic state identity. It does not by itself prove:

- evidence completeness;
- signer trustworthiness;
- governance correctness;
- capture completeness;
- storage durability;
- hardware or network independence;
- correct domain semantics.
