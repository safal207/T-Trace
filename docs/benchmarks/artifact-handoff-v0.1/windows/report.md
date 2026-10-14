# Artifact handoff performance baseline

Mode: **baseline**.

These are source-backed byte-API and module/Node CLI measurements on public
synthetic inputs, not production SLAs, installed-console startup measurements,
external-user onboarding time or proof of an external deployment.

Environment: Windows / AMD64; Python 3.12.10; Node v24.19.0.
Measured source inventory SHA-256: `271db12fdee586d0587ab909e7aec19632c4951a8b4fe673d1af901eaf4c2916`.

| Artifact bytes | Runtime | API median / p95 ms | Fresh CLI median / p95 ms | Worker peak MiB | Package / context bytes |
|---:|---|---:|---:|---:|---:|
| 75 | python | 0.642 / 0.915 | 134.690 / 141.586 | 27.2 | 1804 / 2220 |
| 75 | node | 0.698 / 1.421 | 67.352 / 76.801 | 42.0 | 1804 / 2220 |
| 65536 | python | 0.732 / 0.874 | 136.624 / 147.000 | 27.2 | 67274 / 2223 |
| 65536 | node | 0.850 / 1.553 | 68.785 / 76.851 | 42.2 | 67274 / 2223 |
| 1048576 | python | 2.152 / 2.497 | 140.625 / 154.057 | 28.2 | 1050320 / 2225 |
| 1048576 | node | 2.413 / 2.849 | 69.580 / 83.751 | 49.4 | 1050320 / 2225 |

## Method and limitations

Each implementation/input/round uses a fresh API worker and one unmeasured
reference verification in addition to the stated warmups. Files are loaded before
API timing; parsing, hashes, signatures and decision computation are timed.
Per-call report serialization/comparison is outside that timer. Worker peak memory
includes the runtime, imports, loaded data, checks, warmups and measured calls;
it is neither incremental verifier heap nor the peak of the separate CLI runs.

Fresh CLI measurements include process startup, file reads, verification, JSON
output capture and process exit. A fresh process is not a cold OS filesystem cache.
Round two reverses input/runtime order. Dependency acquisition and generation are
excluded. Host load, CPU frequency, GC and OS caching are not controlled.

Raw samples, all input sizes/hashes, full-result hashes, source-file identities and
runtime/dependency versions are retained in report.json beside this generated file.
Median/p95 in the table pool rounds; p95 uses the nearest-rank definition.

Report validation recomputes inputs, identities and statistics; it does not
authenticate an unknown publisher or prove that supplied timing samples were
honestly measured. These local results are backed by the actual recorded run.

## Initial review triggers, not automatic approval gates

Time triggers are four times the worst per-round p95: API rounded up to 1 ms,
fresh CLI to 10 ms. Memory is twice the worst worker peak, rounded up to 1 MiB.
Package/context byte budgets are exact for these fixtures. These local-host
triggers require a comparable rerun and investigation; they are not universal
hardware limits or absolute-time CI assertions.

| Artifact bytes | Runtime | API p95 ms | Fresh CLI p95 ms | Worker peak MiB |
|---:|---|---:|---:|---:|
| 75 | python | 4 | 570 | 55 |
| 75 | node | 6 | 310 | 84 |
| 65536 | python | 5 | 590 | 55 |
| 65536 | node | 7 | 310 | 85 |
| 1048576 | python | 11 | 620 | 57 |
| 1048576 | node | 12 | 340 | 99 |
