# Artifact handoff performance baseline

Mode: **baseline**.

These are source-backed byte-API and module/Node CLI measurements on public
synthetic inputs, not production SLAs, installed-console startup measurements,
external-user onboarding time or proof of an external deployment.

Environment: Windows / AMD64; Python 3.12.14; Node v24.19.0.
Measured source inventory SHA-256: `1e7d90aacbdc62ecd3e9180e32ed17b3ec7a7075c0f84559e930dac88db50ea4`.

| Artifact bytes | Runtime | API median / p95 ms | Fresh CLI median / p95 ms | Worker peak MiB | Package / context bytes |
|---:|---|---:|---:|---:|---:|
| 75 | python | 2.988 / 4.410 | 808.499 / 1108.897 | 30.3 | 1804 / 2220 |
| 75 | node | 3.365 / 5.377 | 280.864 / 388.481 | 45.4 | 1804 / 2220 |
| 65536 | python | 3.375 / 4.270 | 934.747 / 1258.925 | 30.6 | 67274 / 2223 |
| 65536 | node | 3.546 / 5.625 | 322.566 / 428.861 | 45.7 | 67274 / 2223 |
| 1048576 | python | 6.614 / 7.971 | 794.965 / 917.202 | 31.3 | 1050320 / 2225 |
| 1048576 | node | 7.397 / 9.536 | 328.071 / 350.771 | 52.2 | 1050320 / 2225 |

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
| 75 | python | 19 | 4440 | 61 |
| 75 | node | 26 | 1560 | 91 |
| 65536 | python | 22 | 5040 | 62 |
| 65536 | node | 25 | 1720 | 92 |
| 1048576 | python | 33 | 3670 | 63 |
| 1048576 | node | 43 | 1410 | 105 |
