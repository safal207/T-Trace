# T-Trace Specifications

This directory contains the normative and draft protocol specifications for T-Trace.

## Specifications

- [`t-trace.md`](t-trace.md) — T-Trace v0.1 base specification for append-only acknowledged state transitions.
- [`causal-execution-graph-v0.1.md`](causal-execution-graph-v0.1.md) — draft distributed execution profile for causal ordering, retries, re-resolution, fork/merge, recovery, and portable verification.
- [`portable-causality-profile-v0.1.md`](portable-causality-profile-v0.1.md) — draft canonical identity profile for semantic state, transitions, genuine forks, and explicit two-parent reconciliation.

## Layering

```text
T-Trace v0.1 record envelope
        ↓
Causal Execution Graph Profile
        ↓
Portable Causality Profile
```

The base validator remains unchanged. Profiles add domain payload semantics and focused verifiers without silently changing T-Trace v0.1 wire compatibility.

## Core principles

> **A portable execution record is a causally ordered execution graph, not a linear audit log.**

> **Evidence proves a causal state; evidence does not become the causal state's portable identity.**

The distributed profiles distinguish:

- logical operation from concrete execution attempt;
- wall-clock description from causal authority;
- provider evidence from portable semantic identity;
- historical generation from causal epoch;
- one-parent transition from multi-parent reconciliation.
