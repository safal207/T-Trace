# T-Trace Specifications

This directory contains normative and draft protocol specifications for T-Trace.

## Base protocol

- [`t-trace.md`](t-trace.md) — T-Trace v0.1 base specification for append-only acknowledged state transitions.

## Distributed execution profile

- [`causal-execution-graph-v0.1.md`](causal-execution-graph-v0.1.md) — distributed execution profile for causal ordering, retries, re-resolution, fork/merge, recovery, and portable verification.

Core principle:

> **A portable execution record is a causally ordered execution graph, not a linear audit log.**

## Portable causality profiles

- [`portable-causal-state-v0.1.md`](portable-causal-state-v0.1.md) — history-free semantic state identity through `CausalStateRef`.
- [`portable-causal-transition-v0.1.md`](portable-causal-transition-v0.1.md) — portable transition identity through `CausalTransitionRef` and full-prefix validation requirements.
- [`causal-fork-reconciliation-v0.1.md`](causal-fork-reconciliation-v0.1.md) — explicit divergent branches and canonical two-parent reconciliation.

These profiles preserve three separate identity layers:

```text
semantic state identity
        ≠
portable transition / reconciliation identity
        ≠
provider-specific evidence provenance
```

They are intentionally separate from the original v0.1 JSONL validator. The existing base protocol and examples remain backward-compatible.

## Reference implementation

The draft profiles are implemented in `ttrace/` and exercised by:

```bash
python -m pytest -q tests/test_portable_causality.py
python scripts/verify_portable_causality.py \
  examples/portable-causal/two-parent-reconciliation.json
```

Research provenance and claim boundaries are recorded in [`../proofs/liminal-research-provenance.md`](../proofs/liminal-research-provenance.md).
