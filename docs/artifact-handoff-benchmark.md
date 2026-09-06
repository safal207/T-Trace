# Reproduce the selected handoff resource baseline

This measures the supported source-backed byte APIs and documented Python
module/Node CLIs for [artifact-handoff/v1](../spec/artifact-handoff-profile-v0.1.md).
It is not a production load test, a wheel-console startup benchmark, an external
pilot or a new human reviewer's setup-time result. The separate clean-install
gates still test portability; installation/download cost is excluded here.

## Run

From the selected source checkout, use the tested Python/Node runtime and pinned
receipt dependencies from the [second-implementation guide](artifact-handoff-node.md).
Use a new output directory; an existing directory is rejected, not overwritten.

```sh
python scripts/benchmark_artifact_handoff.py run /path/to/new-baseline \
  --node /absolute/path/to/node
python scripts/benchmark_artifact_handoff.py validate /path/to/new-baseline/report.json
```

On Windows provide the actual `node.exe` path. The output contains `report.json`,
`report.md`, and `inputs/` with each original package and its separately selected
receiver context. The 75-byte input preserves the existing matching fixture.
The 64 KiB and 1 MiB artifacts are the byte sequence 0..255 repeated exactly;
each has freshly generated deterministic public-test-key signatures and the
fixed synthetic context. All inputs are harmless public benchmark data.
These generated signing fixtures are not a claim of three real deployments.

Before timing, the two implementations must reproduce the same **complete**
report and a supported-under-receiver-context outcome with both native signatures
and historical/current role authorizations. Every timed result is checked again.
Negative/insufficient results or changed input hashes abort the measurement.

## Measurement contract

- Two rounds reverse input and runtime order. Each of the six runtime/size
  combinations has a fresh worker in each round, one reference verification,
  five additional untimed warmups and 30 API samples: 60 recorded API samples
  per combination in the pooled summary.
- A separate fresh-process CLI runs five times per combination/round: ten
  startup-to-exit samples. File reads and output capture are included; parsing
  the captured result for comparison is outside that timer. The OS filesystem
  cache is uncontrolled. Fresh process does not mean cold disk or CPU cache.
- Whole-process peak resident/working-set memory is queried in each API worker,
  including its runtime, loaded inputs, checks and instrumentation. It is not
  incremental heap memory and does not claim the peak of the separate CLI runs.
  Windows Python uses Microsoft's
  [PeakWorkingSetSize in bytes](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).
  Linux Python uses `getrusage(RUSAGE_SELF).ru_maxrss` in KiB. Node's
  [process.resourceUsage().maxRSS](https://nodejs.org/docs/latest-v24.x/api/process.html#processresourceusage)
  is in KiB; values are multiplied by 1024. Unsupported/unavailable measurements
  fail rather than reporting zero or quietly substituting a heap tracker.
- Package bytes are the sum of actual artifact, manifest and receipt files.
  Receiver-context bytes are recorded separately; neither compressed size nor
  filesystem allocation is substituted for original byte length.
- Monotonic timers record integer nanoseconds. Raw samples, nearest-rank p95,
  median/min/max, actual source-file hashes, runtime/dependency versions and
  each input/result identity are retained. Source identity covers the runtime
  project modules and benchmark instrumentation, not third-party binary hashes.
  `repository_base_commit` gives the checkout's commit; the full file inventory
  identifies the measured bytes even when benchmark work was uncommitted.

Keep inputs and source files stable during a run. Host load, clock frequency,
GC, security software and scheduling can affect results. Two rounds expose
some noise but do not establish a latency distribution for production traffic.
Do not interpret the source-file hash or report validator as authentication of
an unknown publisher's measurement claims.

## Initial budgets and CI

After measuring, the tool derives local-host review triggers from the worst
per-round p95, not from an invented target: four times API p95 rounded upward
to 1 ms; four times fresh-CLI p95 rounded upward to 10 ms. The memory trigger is
twice the worst worker peak, rounded upward to 1 MiB. Package/context byte
budgets are exact for each fixed input. A breach warrants a comparable rerun
and investigation, not rejection of a valid artifact or an automatic claim of
a production regression on different hardware.

CI uses a separately labelled smoke mode (one round, three API samples and one
fresh CLI sample per combination) to check the pipeline. Smoke output cannot
be validated as a full baseline and has no derived budgets. No absolute speed
threshold is asserted on heterogeneous hosted runners. Unit tests independently
check sample arithmetic, fixed byte sizes, result identities, ordering, units,
cardinality, missing/duplicate data and baseline-derived budgets.
