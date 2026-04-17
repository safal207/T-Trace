# T-Trace v0.1 Specification

## 1. Purpose

T-Trace is a protocol-agnostic, append-only JSONL format for recording acknowledged state transitions.

Its goal is to preserve continuity, causality, and auditability across long-running threads.

## 2. Terms

- **Thread**: a continuity context identified by `thread_id`.
- **Record**: one JSON object line in a T-Trace stream.
- **Transition**: a proposed state evolution.
- **Commit**: acknowledgement/finalization of a transition.
- **Sense**: admission of external input into thread context.

## 3. Wire Format

T-Trace MUST be encoded as newline-delimited JSON (JSONL).

Each record MUST be a JSON object with at least:

- `id` (string): unique trace identifier
- `type` (string): one of `sense`, `transition`, `commit`
- `ts` (string|number): ISO 8601 timestamp or unix epoch
- `thread_id` (string): thread continuity key

Additional fields MAY be included as domain payload.

## 4. Canonical Types

- `sense` - introduces external signal/input
- `transition` - proposes state change
- `commit` - acknowledges/finalizes state change

## 5. Normative Invariants

1. **Append-only**: prior records are immutable.
2. **Line validity**: each non-empty line MUST parse as JSON object.
3. **Type validity**: `type` MUST be in canonical set.
4. **ID uniqueness**: `id` MUST be unique per trace file.
5. **Per-thread monotonic time**: `ts` MUST not decrease within a thread.
6. **Transition causality**: `transition` SHOULD follow prior `sense` or `transition` in same thread.
7. **Commit causality**: `commit` SHOULD follow prior `transition` in same thread.

## 6. Scope

T-Trace defines record structure and invariants only.

Transport, storage backend, cryptographic signing, and access control are out of scope for v0.1.