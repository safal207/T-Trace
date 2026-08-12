# T-Trace Causal Execution Graph Profile v0.1

**Status:** Draft normative profile  
**Scope:** protocol-agnostic portable execution records for distributed, multi-agent, multi-server workflows

## 1. Purpose

A portable execution record MUST preserve **causal meaning**, not merely a visually ordered list of timestamped events.

This profile defines a minimal causal spine for workflows in which an agent may resolve tools dynamically, execute across multiple servers, retry after ambiguous failures, fork into parallel branches, merge results, recover, or re-drive a semantic operation.

The central rule is:

> **A portable execution record is a causally ordered execution graph, not a linear audit log.**

Wall-clock timestamps describe time. They MUST NOT be treated as the authority for cross-emitter execution order.

## 2. Design principle

For distributed execution, the portable model is a **partial order**.

Let `A ≺ B` mean "A happened-before B" for verification purposes.

`A ≺ B` MAY be established by:

1. an explicit causal-parent / causal-ancestor reference;
2. an evidence reference that cryptographically or semantically binds B to A;
3. an emitter-local monotonic sequence edge when both records are produced by the same emitter and sequence namespace;
4. the transitive closure of the above.

`A ≺ B` MUST NOT be inferred solely from `valid_time`, `recorded_time`, or another wall-clock timestamp.

Two records with no causal path between them MAY remain concurrent. A conforming verifier MUST NOT invent a total order between them.

## 3. Minimal causal spine

A conforming record SHOULD expose the following semantic fields directly or through stable digests/references.

### 3.1 Identity

- `record_id` — unique identity of this record.
- `logical_operation_id` — stable identity of the semantic operation across retries, re-drives, recovery, or repeated execution attempts.
- `execution_id` — identity of one concrete execution attempt.
- `attempt` — optional monotonic attempt number within a logical operation.

`logical_operation_id` and `execution_id` MUST NOT be treated as synonyms.

A timeout followed by a re-drive SHOULD normally create a new `execution_id` under the same `logical_operation_id`, unless the caller has evidence that the original attempt never entered execution.

### 3.2 Causal position

- `parent_refs` — zero or more direct causal parents.
- `divergent_ancestor_ref` — optional exact ancestor from which a retry, recovery path, re-resolution, or fork diverged.
- `emitter_id` — stable identity of the component producing the record.
- `emitter_seq` — optional monotonic sequence number local to `emitter_id` and its declared sequence namespace.

A record MAY have multiple parents. Multi-parent records represent merge/confluence points. Therefore the portable lineage model is a DAG, not necessarily a tree.

### 3.3 Intent

`intent` describes what semantic operation was requested or authorized.

It SHOULD be represented as canonical data or a stable digest plus resolvable evidence reference.

The purpose of `intent` is to distinguish:

> "the requested operation executed"

from:

> "an agent executed something adjacent to the request."

### 3.4 Resolution

`resolution` describes what the system actually selected for execution, for example:

- server / endpoint;
- tool / capability;
- normalized parameters;
- tool or server version;
- policy version;
- model or planner version when material;
- stable digests of the above when raw values cannot be retained.

Intent and resolution MUST remain distinguishable.

### 3.5 Expected outcome / invariants

`expected` SHOULD identify the expected outcome class and/or invariants that define acceptable execution.

Examples include:

- expected state transition;
- allowed mutation class;
- spending or approval invariant;
- idempotency requirement;
- "rejected request implies no state mutation";
- consistency requirement between API state, ledger, webhook, and audit evidence.

### 3.6 Observed outcome

`observed` records the externally or independently observable result of the execution attempt.

Observed outcome SHOULD distinguish at least:

- success;
- rejection;
- failure;
- timeout / unknown disposition;
- partial effect;
- recovery / compensation result.

A timeout MUST NOT automatically be interpreted as "no effect".

### 3.7 Phase and disposition

- `phase` — lifecycle phase such as `intent`, `resolved`, `dispatched`, `effect`, `verified`, `recovery`, `closed`.
- `disposition` — current semantic disposition such as `pending`, `succeeded`, `rejected`, `unknown`, `recovering`, `compensated`, `failed`.

Phase is about where the operation is in its lifecycle. Disposition is about what is currently believed about its outcome.

### 3.8 Time

- `valid_time` — time at which the represented fact or effect is considered valid in the domain.
- `recorded_time` — time at which the emitter recorded the statement.

These fields are descriptive. They MAY be useful for freshness, latency, expiration, policy windows, or dispute analysis.

They MUST NOT establish cross-emitter causal order by themselves.

### 3.9 Verification and evidence

- `verification_refs` — references to verifier outputs, attestations, proofs, checks, or independent observations.
- `evidence_refs` — references or digests binding the record to retained evidence.

Profiles MAY enrich evidence semantics, but MUST NOT remove the causal chain required to interpret the execution.

## 4. Normative invariants

### I1. Causal acyclicity

The directed graph induced by causal parents MUST be acyclic.

A verifier MUST reject a record set whose declared causal edges create a cycle.

### I2. Timestamp non-authority

A verifier MUST NOT reject an otherwise coherent causal graph solely because independent wall-clock timestamps disagree with the causal order.

Example:

```text
dispatch(A) @ 10:00:00.900
effect(B)   @ 10:00:00.650
verify(C)   @ 10:00:01.100
```

If `A ≺ B ≺ C` is established by causal references, the earlier wall-clock timestamp on B is clock skew, not evidence that B preceded A.

### I3. Concurrency preservation

If neither `A ≺ B` nor `B ≺ A` can be established, the records MUST be allowed to remain unordered/concurrent.

A serializer MAY choose a deterministic presentation order, but that order MUST NOT be promoted into execution semantics.

### I4. Logical operation continuity

Retries, re-drives, or recovery attempts that continue the same semantic operation SHOULD preserve `logical_operation_id` and create distinct `execution_id` values.

A verifier SHOULD flag multiple independent logical operations that appear to be accidental duplicates when the evidence indicates they are retries of the same semantic request.

### I5. Material re-resolution is a state transition

If a new attempt under the same `logical_operation_id` resolves to materially different target, parameters, version, policy, authority, or other execution semantics, the change MUST be represented explicitly as a new causal state transition.

It MUST NOT be treated as an opaque continuation.

The changed resolution SHOULD require re-verification against the intent and expected invariants before the new effect is accepted as equivalent to the prior attempt.

### I6. Exact divergence reference

When execution diverges because of retry, fallback, recovery, tool re-resolution, or version drift, the record SHOULD reference the exact divergent ancestor rather than only the workflow root.

This makes the first point of semantic divergence mechanically resolvable across servers.

### I7. Outcome binds to resolution

An observed outcome MUST be attributable to the concrete execution/resolution that produced it.

A verifier MUST NOT silently apply an outcome produced under one target/version/parameter set to a materially different resolution.

### I8. Merge transparency

When an output depends on multiple causal branches, the merge/confluence record SHOULD include all material parent references.

A merge MUST NOT erase lineage that would change governance, authorization, sensitivity, or verification conclusions.

### I9. Emitter-local sequence consistency

If `emitter_seq` is present, it MUST be monotonic within the declared emitter sequence namespace.

A contradiction between declared emitter-local sequence and declared causal ancestry is a verification failure.

### I10. Unknown disposition remains unknown

Ambiguous transport outcomes such as timeouts, lost responses, or disconnected clients MUST NOT be rewritten as "failed with no effect" unless evidence establishes that conclusion.

Recovery logic MUST preserve uncertainty until the effect is verified, compensated, or otherwise resolved.

## 5. Minimal record example

The exact wire schema is profile-specific. The following JSON is illustrative:

```json
{
  "record_id": "rec-0042",
  "logical_operation_id": "op-pay-731",
  "execution_id": "exec-731-b",
  "attempt": 2,
  "emitter_id": "agent-gateway-2",
  "emitter_seq": 8841,
  "parent_refs": ["rec-0038"],
  "divergent_ancestor_ref": "rec-0035",
  "phase": "resolved",
  "intent": {
    "digest": "sha256:intent..."
  },
  "resolution": {
    "server": "payments-b",
    "tool": "wallet.spend",
    "version": "2.4.1",
    "params_digest": "sha256:params..."
  },
  "expected": {
    "outcome_class": "single-authorized-transfer",
    "invariants": [
      "no duplicate settlement",
      "amount <= delegated limit"
    ]
  },
  "observed": {
    "status": "pending"
  },
  "disposition": "pending",
  "valid_time": "2026-08-12T10:00:00.650Z",
  "recorded_time": "2026-08-12T10:00:00.900Z",
  "verification_refs": [],
  "evidence_refs": ["sha256:evidence..."]
}
```

The timestamps do not define whether this record precedes or follows another emitter's record. `parent_refs`, `emitter_seq`, and evidence relationships do.

## 6. Retry / re-resolution example

Consider one semantic payment operation:

```text
intent(op-17)
   |
resolve A(tool=v1, server=S1)
   |
execute e1
   |
timeout / disposition unknown
   |
   +---- retry under same logical_operation_id ----+
                                                   |
                                      resolve B(tool=v2, server=S2)
                                                   |
                                      re-verify intent + invariants
                                                   |
                                             execute e2
                                                   |
                                              verify effect
```

Requirements:

- both attempts share `logical_operation_id = op-17`;
- `e1` and `e2` have different `execution_id` values;
- the new tool/server/version is an explicit re-resolution transition;
- the retry points to the exact ancestor where the path diverged;
- the timeout remains semantically `unknown` until evidence resolves whether e1 produced an effect;
- verification MUST consider duplicate-effect/idempotency risk across both attempts.

This prevents a retry from being misread as either a new user intent or an invisible continuation.

## 7. Fork / merge example

```text
                  +--> branch B -->+
intent --> resolve                 merge --> verify
                  +--> branch C -->+
```

B and C are concurrent unless a causal edge states otherwise.

Their timestamps MAY interleave in any order. A merge record MUST identify both material parents when both branches influence the result.

## 8. Offline verifier behavior

A conforming offline verifier SHOULD be able to validate, from the portable record set and retained material alone:

1. record identity uniqueness;
2. causal parent resolvability or explicit external-reference status;
3. causal DAG acyclicity;
4. emitter-local sequence consistency when present;
5. logical-operation / execution-attempt separation;
6. explicit representation of material re-resolution;
7. exact divergence ancestry when supplied;
8. outcome-to-resolution binding;
9. merge lineage completeness according to the active profile;
10. evidence-reference integrity where retained material is available.

The verifier MUST NOT require synchronized wall clocks to reconstruct the causal graph.

## 9. Relationship to T-Trace v0.1

T-Trace v0.1 currently defines per-thread timestamp monotonicity for its simple linear JSONL trace model.

This Causal Execution Graph Profile intentionally does **not** use wall-clock monotonicity as distributed causal authority. For multi-emitter or multi-server traces, implementations SHOULD use explicit causal references and emitter-local sequence numbers.

A future T-Trace revision may promote these semantics into the base protocol after the schema, examples, validator, and compatibility rules are updated together.

This profile therefore avoids silently changing v0.1 validator behavior while making the distributed causal model explicit and independently referenceable.

## 10. Non-goals

This profile does not prescribe:

- a cryptographic signature algorithm;
- a transport protocol;
- a storage backend;
- an authorization framework;
- a global clock;
- a total event order;
- domain-specific governance policy.

Those MAY be defined by extensions or profiles, provided they do not erase or contradict the causal spine.

## 11. Summary

The portable contract is:

```text
logical operation
  -> intent
  -> resolution
  -> execution attempt
  -> observed effect/outcome
  -> verification
  -> recovery/disposition when required
```

with explicit causal edges, fork/merge support, retry identity, material re-resolution transitions, and evidence references.

**Causality establishes order. Time describes it.**
