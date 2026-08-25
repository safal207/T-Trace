# Threat Model — Portable Causality Profiles

## Assets

The profiles protect the meaning and lineage of acknowledged state transitions across retries, independent evidence paths, forks, and reconciliation.

Protected assets include:

- semantic state identity;
- exact transition identity;
- causal epoch continuity;
- branch lineage completeness;
- exact vote-to-branch binding;
- deterministic portable bytes;
- separation between portable identity and raw provenance.

## Trust assumptions

The reference implementation assumes that an upstream verifier has already decided whether an evidence envelope is authentic and acceptable. `BranchObservation.verified = true` represents that upstream decision; it is not a cryptographic signature check by itself.

The implementation does not decide whether an authority is socially legitimate or whether the target semantic state is good policy.

## Threats and mitigations

| Threat | Failure mode | Mitigation |
|---|---|---|
| Provenance promoted into identity | Equivalent systems cannot converge | Portable state and transition refs exclude provider, signer, registry, manifest, and history generation |
| History count treated as causal progress | No-op metadata changes advance the protocol | Causal epoch advances only for a different semantic state |
| Epoch skipping | Missing transition is hidden | Exact `+1` epoch invariant |
| Branch omission | Reconciliation silently forgets one lineage | Two distinct parent checkpoint and witness digests are mandatory |
| Duplicate parent | One lineage masquerades as two approvals | Parent digests must be distinct |
| Vote rebinding | Approval for branch A is applied to branch B | Vote commits branch ref, state, checkpoint, and witness digests |
| Target substitution | Authorities appear to approve a state they did not approve | Both votes commit the same exact target semantic digest |
| Contract substitution | Reconciliation semantics change after approval | Votes commit reconciliation and authorization contracts |
| Input-order ambiguity | Same parents produce different identities | Parents are sorted by checkpoint digest |
| Raw evidence smuggling | Provider identity re-enters portable identity through a logical field | Strict object shapes and negative tests; portable result contains no provider/authority/evidence fields |
| Tampered common ancestor | Branches are joined from different causal roots | Each branch binds the exact common state, checkpoint, and witness |
| Selective capture | A valid trace omits a real-world effect | Out of scope for these objects; use T-Trace assurance profiles and independent capture evidence |

## Fail-closed posture

The implementation raises a deterministic validation error rather than selecting a winner when branch evidence, vote bindings, target, contracts, epochs, or parent sets are ambiguous.

## Current assurance boundary

The native T-Trace code in this repository proves deterministic construction and validation of the reference objects. The larger independent-provider and cryptographic-attestation experiments that motivated the design are recorded separately in `proofs/liminal-research-provenance.md`.

A future T-Trace-native proof workflow should reproduce those cryptographic independence claims from this repository rather than relying permanently on the Liminal research repository.
