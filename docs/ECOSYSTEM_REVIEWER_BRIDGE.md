# T-Trace Ecosystem Reviewer Bridge

This note is for reviewers who entered through T-Trace and need to understand how it fits into the broader LS / ProofPath ecosystem.

T-Trace is the append-only transition-record and validation layer. It provides a small, machine-checkable protocol for acknowledged state transitions over time.

It should be read as a supporting integrity and trace-format layer, not as the whole ecosystem.

## Role in the ecosystem

```text
LS / Liminal Stack
  -> broad governance, coordination, continuity, and reviewer surface

ProofPath / Compute Witness
  -> current executable evidence hub for action boundaries and reviewable compute evidence

CML / Causal Memory Layer
  -> causal-validity and why-allowed layer

LTP / L-THREAD
  -> trace/replay/continuity and admissibility-inspection layer

T-Trace
  -> append-only transition-record and validation layer
```

## What T-Trace contributes

T-Trace focuses on the record substrate:

```text
acknowledged state transition
  -> strict JSONL record envelope
  -> per-thread continuity
  -> transition / commit causality checks
  -> validator regression tests
  -> replayable evidence surface
```

T-Trace is useful when a reviewer needs to distinguish between:

```text
raw events or logs
```

and:

```text
acknowledged state transitions that can be validated and replayed
```

## Relationship to ProofPath / Compute Witness

ProofPath and Compute Witness provide the current executable evidence hub:

```text
job manifest
-> compute receipt
-> audit evidence
-> verifier decision
-> CI regression check
```

T-Trace complements that by focusing on the transition-record format and validation invariants that can support trace integrity across adjacent systems.

In short:

```text
ProofPath asks: should this action execute?
Compute Witness asks: can this compute result be trusted as reviewable evidence?
T-Trace asks: can the acknowledged transition history be represented and validated consistently?
```

## Relationship to LS

LS is the broader reviewer and governance surface. It frames the human-owned coordination, continuity, safety-gate, and grant-review story.

Use the LS grant packet for the funder-facing overview:

- LS Grant Reviewer Packet 2026: https://github.com/safal207/LS/blob/main/docs/GRANT_REVIEWER_PACKET_2026.md
- LS Ecosystem Reviewer Index: https://github.com/safal207/LS/blob/main/docs/ECOSYSTEM_REVIEWER_INDEX.md

## Relationship to LTP

LTP focuses on deterministic replay, trace inspection, and admissibility decisions for agent execution paths.

T-Trace is narrower:

```text
T-Trace
  -> transition record shape and validation invariants

LTP
  -> replay / inspection protocol and admissibility decisions
```

A practical relationship is:

```text
T-Trace records acknowledged transitions.
LTP inspects and replays higher-level execution paths.
```

## Relationship to CML

CML focuses on causal permission and why-allowed lineage.

T-Trace focuses on the append-only transition record.

A practical relationship is:

```text
CML explains why a transition was allowed.
T-Trace records that the transition was acknowledged in a verifiable sequence.
```

## Direct reviewer links

- ProofPath Ecosystem Graph: https://github.com/safal207/ProofPath/blob/main/docs/ECOSYSTEM_GRAPH.md
- LS Grant Reviewer Packet 2026: https://github.com/safal207/LS/blob/main/docs/GRANT_REVIEWER_PACKET_2026.md
- LS Ecosystem Reviewer Index: https://github.com/safal207/LS/blob/main/docs/ECOSYSTEM_REVIEWER_INDEX.md
- ProofPath / Compute Witness: https://github.com/safal207/ProofPath
- Causal Memory Layer: https://github.com/safal207/Causal-Memory-Layer
- LTP / L-THREAD: https://github.com/safal207/L-THREAD-Liminal-Thread-Secure-Protocol-LTP-

## What this bridge does not claim

This bridge does not claim that T-Trace is a full production compliance platform.

It also does not claim:

- universal trace semantics;
- complete replay of arbitrary systems;
- production key management;
- certified regulatory compliance;
- distributed consensus;
- TEE or hardware attestation;
- model truthfulness;
- full end-to-end agent alignment.

The current claim is narrower:

```text
T-Trace provides a small append-only JSONL protocol and reference validator for acknowledged state transitions, and it can serve as a transition-record layer inside the broader LS / ProofPath evidence ecosystem.
```

## Reviewer phrase

```text
T-Trace is the append-only transition-record and validation layer in the ecosystem; ProofPath / Compute Witness is the current executable evidence hub; LS is the broad grant-reviewer surface.
```
