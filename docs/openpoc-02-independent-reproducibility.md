# OpenPoC-02 — Claim-scoped independent reproducibility

## Claim under test

A third party can independently execute a bound recipe over bound inputs under
a declared runtime contract and either reproduce or falsify the claimed
output.

That claim is deliberately narrower than:

> the supplied inputs contain every relevant real-world effect.

OpenPoC-02 keeps those questions separate and makes their composition
explicit through `claim.required_dimensions`.

## Scenarios

| Scenario | Replay relation | Capture inventory | Claim verdict |
|---|---:|---:|---|
| Complete bound replay | satisfied | supported under gate assumptions | `supported-under-stated-assumptions` |
| Incomplete but reproducible | satisfied | hidden effect detected | `violated` |
| Bound wrong output | falsified | supported under gate assumptions | `violated` |
| Unavailable declared environment | not executed | not evaluated | `insufficient` |

The key negative vector is **incomplete but reproducible**. Its recipe, input,
expected output, and fixture-assumed evidence markers are internally
consistent. Independent replay succeeds for the exact supplied input. An
independent fixture inventory nevertheless exposes `effect-hidden`, so the
broader claim about all external effects fails.

## Run

```bash
python -m openpoc.verify_reproducibility \
  examples/openpoc-02/complete-replay.scenario.json

python -m openpoc.verify_reproducibility \
  examples/openpoc-02/incomplete-but-reproducible.scenario.json
```

Expected core result for the incomplete case:

```json
{
  "artifact_bindings_valid": true,
  "replay_executed": true,
  "relation_satisfied": true,
  "reproduction_status": "supported-under-stated-assumptions",
  "capture_status": "violated",
  "record_integrity_status": "assumed-valid-for-boundary-test",
  "claim_verdict": "violated",
  "missing_effect_ids": ["effect-hidden"]
}
```

## Claim profile

Every scenario declares:

- `property` — the exact statement under test;
- `scope` — the resource and run to which it applies;
- `confidence_target` — the requested kind of assurance;
- `adversary_model` — controlled and excluded capabilities;
- `required_dimensions` — the assurance dimensions needed for the claim.

The verifier does not emit a context-free overall `PASS`. It computes
reproducibility, capture completeness, and record integrity separately, then
derives a claim-scoped verdict from the dimensions the manifest requires.

## Artifact and environment binding

The reference fixture binds:

- the exact recipe bytes by SHA-256;
- the exact input bytes by SHA-256;
- the canonical expected output by SHA-256;
- the replay-engine identifier;
- the minimum Python runtime contract.

The recipe is declarative and intentionally small. It sums a non-negative
integer field over uniquely identified effects. The reference verifier rejects
unsupported schemas or operations, malformed effects, duplicate identifiers,
artifact paths outside the scenario directory, and digest mismatches before
replay.

## Transparency and attestation boundary

`external_evidence` marks producer attestation, transparency inclusion, and
transparency consistency as `fixture-assumed-valid`. The verifier checks that
the submitted input digest matches the bound input but does **not** implement
or pretend to validate a production TEE, SCITT service, PKI, or transparency
log.

This is intentional. The fixture asks whether record-integrity evidence for
the supplied input can establish completeness. It cannot reveal an effect
that never entered that input.

Because these evidence markers are assumptions, their status is
`assumed-valid-for-boundary-test`. A claim that directly requires
`record_integrity` remains `insufficient` until a real evidence adapter
validates the relevant proofs and trust roots.

## Verdict language

- `supported-under-stated-assumptions` — the required checks succeeded, but
  the listed computational or system assumptions still apply;
- `violated` — independent fixture evidence or replay contradicts the claim;
- `unproven` — the available mechanism did not establish the dimension;
- `insufficient` — not every dimension required by the claim was supported.

## Non-claims

OpenPoC-02 does not claim that:

- deterministic replay proves input completeness;
- a digest proves that an external event occurred;
- fixture-assumed transparency or attestation markers are production proofs;
- the verifier is a SNARK, zero-knowledge, TEE, SCITT, or remote-attestation
  implementation;
- reproducibility of a supplied computation proves a broader semantic,
  authorization, policy, or physical-world statement.

The benchmark result is narrower: **a relation can be reproducible over fixed
inputs while a broader capture claim is still unsupported or false.**
