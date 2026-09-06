# Artifact handoff verification

Handoff at the selected cutoff: **supported-under-receiver-context**.
Supplied-snapshot comparison: **consistent-in-supplied-snapshots**.

Receiver context SHA-256: `2de8aebacc8d2b28d5e0f50032d6eb3bd6ded106c7d40eb95163e40e20430840`.
Transport manifest SHA-256: `377066ece738ca2775663a37978d648a87c399964d89dfe690dc9174f45e117f`.
Audit cutoff (Unix ms): `1788694202000`; evaluation time: `1788694204000`.

| Role | Signature | Expected claim | Historical authority | Current authority |
|---|---|---|---|---|
| sender | valid | matches-expected-handoff | authorized-at-observation | authorized-for-current-policy |
| receiver | valid | matches-expected-handoff | authorized-at-observation | authorized-for-current-policy |

## How to use this result

The receiver must independently accept the policy archive, key-status completeness,
observation times and snapshot finality. Matching the package manifest alone is not
publisher authentication. Historical authority is evaluated at the accepted observation
time, not an independently proved execution/signing instant. Current authority is a
separate result and is not permission to execute a new action.

Missing evidence is not approval. A late receipt cannot repair an earlier snapshot.
The report does not prove global capture completeness, real-world effect truth,
production non-bypassability, independent organizations, or an external pilot.
