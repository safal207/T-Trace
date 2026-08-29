# Changelog

## Unreleased

- Added Witness-Set Rotation / Quorum-Handoff Portability Profile v0.1.
- Added exact old-policy and new-policy dual-quorum authorization over one lineage view and one policy transition.
- Added direct old-active→handoff and handoff→new-activation witness predecessor continuity.
- Added canonical handoff certificates, supplied-view conflicting-rotation evidence, and rejection of unused handoff observations.
- Preserved `global_non_equivocation_status = unproven` and made policy handoff safety conditional on authenticated evidence and quorum assumptions.
- Added Witness-Quorum Anchor / Conditional Non-Equivocation Profile v0.1.
- Added exact threshold policies with guaranteed quorum intersection and strict JSON integer semantics.
- Added canonical externally verified witness observations and recomputed quorum certificates over exact producer anchor statements.
- Added direct intersecting-witness sequence/predecessor continuity for append-only root transitions.
- Added bounded producer split-view evidence with attributable overlapping witness observations while preserving `global_non_equivocation_status = unproven`.
- Added Membership-Root Consistency / Anti-Equivocation Profile v0.1.
- Added compact-frontier append-only proofs between existing lineage-membership roots.
- Added endpoint current-cycle membership binding for both consistency-proof roots.
- Added normalized externally verified anchor statements and bounded split-view evidence.
- Preserved `global_non_equivocation_status = unproven` without gossip or witness comparison.
- Added Lineage Membership / Selective Historical Disclosure Profile v0.1.
- Added fixed-shape repeated fork/reconciliation lineage compaction.
- Added OpenPoC-02 claim-scoped independent-reproducibility fixtures.
- Added bound recipe, input, output, and runtime verification with fail-closed tests.
- Added a negative vector where replay succeeds over an incomplete input while capture completeness fails.
- Replaced unconditional gated-fixture verdict language with `supported-under-stated-assumptions`.
- Added the draft Portable Causality Profile v0.1.
- Added canonical `StateRef`, `TransitionRef`, fork branch, and two-parent reconciliation reference objects.
- Added a provider-agnostic reference verifier with fail-closed tests and a reproducible example.
- Documented the Liminal research/proof provenance without importing its provider-specific infrastructure.
- Kept the T-Trace v0.1 JSONL validator behavior unchanged.

## v0.1

- Initial specification of the T-Trace format.
- Defined core concepts and invariants.
- Added canonical minimal and forbidden examples.
