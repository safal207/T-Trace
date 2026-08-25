# Liminal research provenance for the Portable Causality Profile

The T-Trace Portable Causality Profile is a deliberately small extraction from a larger research and falsification program developed in [`safal207/Liminal`](https://github.com/safal207/Liminal), primarily in draft PR [`#124`](https://github.com/safal207/Liminal/pull/124).

## Why the code was not copied wholesale

The Liminal branch contains a broad recovery/evidence portability stack, provider-specific workflows, attestation drills, historical trust registries, and many experimental proof fixtures. T-Trace has a narrower responsibility:

```text
append-only acknowledged transitions
+ portable causal identity
+ reference validation
```

The migration therefore keeps the tested protocol primitives and fail-closed invariants while excluding Liminal-specific workflow topology, registry formats, provider plumbing, and experimental policy material.

## Research chain used as source evidence

### History-free portable state identity

- reusable verifier: `65140882f172c53b6556ce9aa7a190f40bacc3bf`
- one-shot: `31767862942`
- result: independently rooted histories produced the same portable causal state without embedding raw history identity.

### Multi-epoch portable evolution

- reusable verifier: `5f5cee5749eaa15814323f563c1544347524d000`
- one-shot: `32637713399`
- result: different historical-generation schedules produced the same two-step portable semantic trajectory and complete causal prefix.

### Fork and two-parent reconciliation

- implementation/falsification gate: `9ec014179132cb1bf5a6f21275583cd50425c96e`
- reusable verifier: `51894987f038e6c24fadf5b3c2768feda4117d6f`
- pinned caller: `c6412f5656fda2edaf9cad907d7af1fb8d312402`
- one-shot: `32861017622`
- result: two independently evidenced and semantically divergent branches reconciled through a canonical two-parent DAG join; a separate job reverified signers and recomputed the proof from bundled artifact bytes.

## Architectural findings carried into T-Trace

```text
provenance ≠ portable state identity
historical generation ≠ causal epoch
object validity ≠ full-chain validity
reconciliation ≠ relaxed linear transition
```

The T-Trace profile generalizes those findings into provider-agnostic objects:

- `StateRef`
- `TransitionRef`
- `ForkBranchRef`
- canonical branch tip
- canonical parent set
- `ReconciliationRef`
- reconciliation receipt

## Claim boundary

The Liminal runs are research evidence for the architecture. They are not automatically proof that every future T-Trace implementation, evidence provider, or deployment is secure.

The T-Trace reference implementation separately tests canonicalization, exact binding, order independence, two-parent lineage preservation, and fail-closed rejection. It intentionally does not reproduce the full Liminal attestation infrastructure.
