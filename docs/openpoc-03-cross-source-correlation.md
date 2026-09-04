# OpenPoC-03 — Cross-source counterpart correlation

## Claim under test

Records from different sources can be joined on a shared correlation ID and
their declared action digests compared to detect a missing or conflicting
counterpart. That bounded mismatch does not prove that the complete real-world
history was captured.

OpenPoC-03 makes the distinction executable without changing the base T-Trace
v0.1 validator.

## Smallest fixture

The fixture contains three records from two supplied source snapshots:

| Correlation ID | Sender snapshot | Receiver snapshot | Result |
|---|---|---|---|
| `comm-1` | present | present, same `action_digest` | matched control |
| `comm-2` | present | absent at the audit cutoff | missing counterpart |

The verifier derives the comparison set from correlation IDs observed in at
least one supplied snapshot. That choice is deliberate: an action omitted by
both sources is invisible to pairwise correlation.

Records outside the declared window are reported separately and cannot repair
or erase the verdict as of the audit cutoff.

## Run

```bash
python -m openpoc.verify_cross_source \
  examples/openpoc-03/counterpart-omission.scenario.json
```

Expected core result:

```json
{
  "trace_valid": true,
  "pairwise_consistency_status": "violated",
  "matched_in_supplied_snapshots": ["comm-1"],
  "missing_counterparts": [
    {
      "correlation_id": "comm-2",
      "counterpart_status": "missing",
      "observed_sides": ["sender"],
      "missing_sides": ["receiver"]
    }
  ],
  "global_completeness_status": "unproven",
  "attribution": "undetermined",
  "overall_assurance": "insufficient-for-global-completeness"
}
```

## Exact supported claim

At the declared audit cutoff, within the two supplied snapshots and the
declared one-sender/one-receiver correlation contract, `comm-2` has a sender
record but no receiver counterpart. The supplied evidence therefore violates
the pairwise counterpart contract for `comm-2`.

This is a bounded cross-source evidence mismatch. Global capture completeness
remains unproven, and responsibility for the mismatch is undetermined.

## What a fully matched result means

`consistent-in-supplied-snapshots` means only that no missing counterpart or
digest conflict was found among the observed correlation IDs in the supplied
comparison window. It must not be rewritten as `complete`, `verified`, or
`globally consistent`.

## Trust assumptions

The fixture treats the following as declared inputs, not production proofs:

- the side-to-source bindings are correct;
- the supplied snapshots are final at the stated audit cutoff;
- equal `action_digest` values identify the same canonical action projection;
- each `correlation_id` binds the same action phase across both sources;
- the one-record-per-side contract correctly accounts for retries and fan-out.

The verifier checks digest syntax and equality only. It does not recompute the
digest from a canonical payload or authenticate its producer, phase, actor,
target, attempt, or provenance.

Authenticated source identities, signed watermarks, transparency logs, or a
trusted execution environment would strengthen these assumptions. Their
presence would still need separate verification.

## Non-claims

OpenPoC-03 does not establish that:

- the underlying action occurred in the real world;
- the receiver omitted it, rather than the sender inventing it or the
  collector losing, filtering, or delaying a record;
- either supplied snapshot is complete or truthful;
- actions omitted by both sources can be detected;
- all relevant entities, layers, retries, or fan-out recipients were compared;
- matching digests prove semantic truth, execution, outcome, or replay safety;
- the source responsible for a mismatch can be identified.

Stronger completeness claims require a separately justified coverage
mechanism, such as non-bypassable effect-point capture, authenticated closed
inventories, or independent execution evidence. Pairwise correlation is a
falsifier for observed mismatches, not a universal proof of completeness.

The CLI exits successfully when the fixture executes and its `expected` block
matches. That process result is not a consistency or completeness verdict; the
JSON fields carry those verdicts.
