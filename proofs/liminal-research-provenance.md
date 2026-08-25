# Research Provenance Imported from Liminal

## Purpose

The portable-causality profiles in T-Trace were distilled from a larger research stack built in `safal207/Liminal`.

This document preserves the evidence trail without copying Liminal's 400+ commit draft PR, CI internals, private signing material, or application-specific recovery code into the product repository.

## Source repository

- Research repository: `https://github.com/safal207/Liminal`
- Research PR: `https://github.com/safal207/Liminal/pull/124`
- Source branch: `agent/recovery-routing-v0-1`

Liminal remains the historical research provenance. T-Trace is the canonical clean protocol and reference implementation.

## Verified research ladder

| Gate | Reusable verifier | One-shot run |
|---|---|---:|
| Upstream Rotation-Authority Portability | `28d96de36267fde8e1c66ce0c5f36c2c30e44813` | `31690895530` |
| Genesis / Historical Trust-Base Portability | `64116d0eea55a874ac7f63b733416df39108d7a7` | `31763346787` |
| Downstream Causal-State Portability | `65140882f172c53b6556ce9aa7a190f40bacc3bf` | `31767862942` |
| Portable Multi-Epoch Causal Evolution | `5f5cee5749eaa15814323f563c1544347524d000` | `32637713399` |
| Causal Fork / Reconciliation Portability | `51894987f038e6c24fadf5b3c2768feda4117d6f` | `32861017622` |

The final fork/reconciliation one-shot rebuilt the upstream chain, generated two semantically divergent branches using different evidence authorities, constructed a canonical two-parent reconciliation, and completed an independent audit job.

## Engineering journal

The corresponding RESONANCE signals are:

- Signal 010 — commit `2b8513e734d79121c57df7f9414f6e2771d09371`
- Signal 011 — commit `4c8277dd28af30eb28704f97aafe34b2c676c19f`
- Signal 012 — commit `f6d8f08ccd136995ea6da0e9a4401de97e4fb434`
- Signal 013 — commit `07d911b9cadf5b5c758cf4bfe64f3f105e4d7b51`
- Signal 014 — commit `6b3a343b5d9e2b9591d2a66093c60bdea0989f20`

Repository: `https://github.com/safal207/RESONANCE`

## What was migrated

T-Trace imports the architecture, invariants, strict canonicalization rules, and fail-closed reference model for:

- `CausalStateRef`;
- `CausalTransitionRef`;
- `ForkBranchRef`;
- branch-bound reconciliation votes;
- `CausalReconciliationRef`;
- canonical two-parent checkpoint and witness sets.

## What was deliberately not migrated

- Liminal application and recovery-routing code;
- hundreds of experimental commits and unrelated files;
- Liminal-specific workflow nesting;
- historical registries and manifests as product identity;
- private signing keys;
- claims that have not yet been reproduced natively in T-Trace.

## Claim boundary

The Liminal runs are historical external evidence for the design process. The T-Trace implementation is a clean reimplementation, not a byte-for-byte copy.

The T-Trace CI introduced with this migration verifies deterministic construction, fail-closed behavior, and the committed canonical example. It does not yet reproduce the full GitHub-OIDC-versus-detached-Ed25519 trust-provider independence experiment inside T-Trace.
