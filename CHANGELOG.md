# Changelog

## Unreleased

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
