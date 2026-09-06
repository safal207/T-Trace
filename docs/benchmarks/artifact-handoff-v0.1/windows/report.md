# Artifact handoff performance baseline

Mode: **baseline**.

These are source-backed byte-API and module/Node CLI measurements on public
synthetic inputs, not production SLAs, installed-console startup measurements,
external-user onboarding time or proof of an external deployment.

Environment: Windows / AMD64; Python 3.12.14; Node v24.19.0.
Measured source inventory SHA-256: `09d6fb2af50577359dfe21867f280715061503df828d4d425927040fbe9eeb30`.

| Artifact bytes | Runtime | API median / p95 ms | Fresh CLI median / p95 ms | Worker peak MiB | Package / context bytes |
|---:|---|---:|---:|---:|---:|
| 75 | python | 2.105 / 3.407 | 641.291 / 690.951 | 27.6 | 1804 / 2220 |
| 75 | node | 2.242 / 4.740 | 241.084 / 288.768 | 46.5 | 1804 / 2220 |
| 65536 | python | 2.262 / 3.553 | 631.857 / 670.225 | 27.8 | 67274 / 2223 |
| 65536 | node | 2.782 / 4.491 | 254.116 / 279.258 | 45.7 | 67274 / 2223 |
| 1048576 | python | 5.527 / 6.679 | 632.051 / 682.515 | 28.7 | 1050320 / 2225 |
| 1048576 | node | 6.162 / 8.169 | 247.395 / 305.364 | 52.3 | 1050320 / 2225 |

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
| 75 | python | 14 | 2770 | 56 |
| 75 | node | 35 | 1160 | 94 |
| 65536 | python | 15 | 2690 | 56 |
| 65536 | node | 19 | 1120 | 92 |
| 1048576 | python | 28 | 2740 | 58 |
| 1048576 | node | 33 | 1230 | 105 |
