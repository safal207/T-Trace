# T-Trace Specifications

This directory contains the normative and draft protocol specifications for T-Trace.

## Specifications

- [`t-trace.md`](t-trace.md) — T-Trace v0.1 base specification for append-only acknowledged state transitions.
- [`causal-execution-graph-v0.1.md`](causal-execution-graph-v0.1.md) — draft distributed execution profile for causal ordering, retries, re-resolution, fork/merge, recovery, and portable verification.

## Causal Execution Graph Profile

Core principle:

> **A portable execution record is a causally ordered execution graph, not a linear audit log.**

The profile defines a minimal causal spine:

```text
logical_operation_id
  -> intent
  -> resolution
  -> execution attempt
  -> observed outcome
  -> verification
  -> recovery/disposition when required
```

It also defines these ordering semantics:

- explicit causal-parent/evidence references establish cross-emitter `happened-before`;
- emitter-local monotonic sequence may order records from the same emitter;
- wall-clock timestamps are descriptive and do not establish cross-server causality;
- causally unrelated branches may remain concurrent;
- material re-resolution under the same logical operation is an explicit state transition that requires re-verification;
- retries preserve `logical_operation_id` but use a distinct `execution_id` for each concrete attempt.

The profile is intentionally separate from the v0.1 base validator until schema, examples, and verifier behavior are upgraded together.
