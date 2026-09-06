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

Records outside the declared window, or observed after the audit cutoff, are
reported separately and cannot repair the verdict as of that cutoff. All
supplied records must still satisfy the profile, including out-of-scope ones.

## Run

```bash
python -m openpoc.verify_cross_source \
  examples/openpoc-03/counterpart-omission.scenario.json

python -m openpoc.verify_cross_source \
  examples/openpoc-03/nonfinal-snapshots.scenario.json

python -m openpoc.verify_cross_source \
  examples/openpoc-03/delayed-observation.scenario.json
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

Under declared snapshot finality at the audit cutoff, within the two supplied snapshots and the
declared one-sender/one-receiver correlation contract, `comm-2` has a sender
record but no receiver counterpart. The supplied evidence therefore violates
the pairwise counterpart contract for `comm-2`.

This is a bounded cross-source evidence mismatch. Global capture completeness
remains unproven, and responsibility for the mismatch is undetermined.

## Time, finality, and supported input contract

The scenario schema is `ttrace.openpoc-cross-source/v1`. Its only fields are
`schema`, `scenario`, `trace`, `comparison`, and optional `expected`.
`comparison` contains exactly `required_sides`, `window_start`, `audit_cutoff`,
and `snapshots_final_at_cutoff`. Finality is a required JSON boolean, not a
coerced string, number, or default assumption.

The selected record profile contains exactly the base envelope fields
`id`, `type`, `ts`, `thread_id` plus `source_id`, `side`, `correlation_id`,
`action_digest`, and `observed_at`. This stricter optional profile does not
change the base T-Trace validator or its extension rules.

- `ts` is the declared record time; it must be in the inclusive interval
  `[window_start, audit_cutoff]` to participate.
- `observed_at` is the declared time the record became available to the audit;
  it must not precede `ts` and must be at or before the cutoff to participate.
- The comparison times and `observed_at` require
  `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` or an explicit `+/-HH:MM` offset (one to six
  fractional digits when present). Equivalent offsets compare as instants.
  `ts` also permits finite numeric Unix epoch seconds; booleans and non-finite
  values are rejected. Clock authenticity/synchronization is not proved.
- In the delayed fixture, a receiver record is dated 10:01:01 but observed at
  10:03:00. It cannot repair the 10:02:00 audit. Moving the cutoff to 10:03:00
  admits it; that is a different audit context, not a rewrite of the past.

| Supplied evidence | Finality declared | Pairwise status |
|---|---|---|
| All observed correlations paired with equal digests | true | `consistent-in-supplied-snapshots` |
| A required counterpart is absent | true | `violated`, counterpart `missing` |
| No presented conflict, finality unknown | false | `insufficient-snapshot-finality`, absent counterpart `pending-finality` |
| A presented in-scope pair has conflicting digests | either | `violated`, counterpart `conflicting` |
| Invalid base envelope | either | `invalid-trace` |
| Invalid profile, duplicate side, or no in-scope records | either | `not-evaluable` |

Finality describes closure of the supplied evidence view, not a guarantee that
all external effects were captured. A false finality declaration can mislead
the comparison; this verifier does not authenticate that declaration.

The loader rejects duplicate JSON keys, non-finite numbers, unsupported
schemas/fields, and trace paths escaping the scenario directory. Paths must
be portable relative paths. Each input file is limited to 8 MiB, and traces
to 10,000 records. These are processing limits, not a measured performance
promise or a proof of producer trust.

## What a fully matched result means

`consistent-in-supplied-snapshots` means only that no missing counterpart or
digest conflict was found among the observed correlation IDs in the supplied
comparison window. It must not be rewritten as `complete`, `verified`, or
`globally consistent`.

## Trust assumptions

The fixture treats the following as declared inputs, not production proofs:

- the side-to-source bindings are correct;
- snapshot finality is caller-declared, not independently authenticated;
- record and observation timestamps use a comparable clock basis;
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
