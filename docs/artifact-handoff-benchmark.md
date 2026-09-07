# Reproduce the selected handoff resource baseline

This measures the supported source-backed byte APIs and documented Python
module/Node CLIs for [artifact-handoff/v1](../spec/artifact-handoff-profile-v0.1.md).
It is not a production load test, a wheel-console startup benchmark, an external
pilot or a new human reviewer's setup-time result. The separate clean-install
gates still test portability; installation/download cost is excluded here.

## Run

The recorded Windows baseline is available as a
[human report](benchmarks/artifact-handoff-v0.1/windows/report.md) and
[machine record with every sample](benchmarks/artifact-handoff-v0.1/windows/report.json).
It was genuinely regenerated on a **GitHub-hosted Windows Server 2022** runner
(AMD64, four logical CPUs), using Python 3.12.10, Node 24.19.0,
cryptography 46.0.4, cffi 2.1.1 and pycparser 3.0. The two full rounds
were collected on source commit `9e24fcbc93343c8c460e21f729dc979cc23d740e`
in [Windows evidence run 34134175179](https://github.com/safal207/T-Trace/actions/runs/34134175179).
The measured-source inventory is
`271db12fdee586d0587ab909e7aec19632c4951a8b4fe673d1af901eaf4c2916`.
The original machine-record SHA-256 is
`a85bd4c7d889dcca2417390b5685784d313cdd69fd578827daeeb16e43ae8fa6`;
the committed machine and generated human reports preserve the collected bytes.
All 695 Python tests (including the 110 instrumentation regressions), standalone
Node tests, full baseline validation and a separate real smoke passed on that runner.

This is a **different host from the prior Windows desktop baseline**, not a
same-host before/after speed comparison. Its derived triggers describe this
host class only; a change between hosts is not evidence of a performance
regression or improvement. Earlier measurements remain in Git history; their
source hashes were not edited to make old samples appear newly measured.
The committed record can be checked with the validator below; fixture bytes
are reproducibly regenerated and their identities compared, not assumed.

From the selected source checkout, use the tested Python/Node runtime and pinned
receipt dependencies from the [second-implementation guide](artifact-handoff-node.md).
Use a fresh checkout that preserves Git blob bytes (disable automatic newline
conversion when cloning on Windows, for example `git -c core.autocrlf=false clone`).
Do not rewrite fixture digests or normalize recorded source identities to hide
a converted checkout. The cited Windows run verified all 295 tracked files
against their Git blob identities before measurement.
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
Only artifact size varies here: receipt count, policy archive shape and key
status remain the controlled example's fixed values. The 1 MiB case is not a
claim of worst-case performance over every admitted context or malformed input.

Before timing, the two implementations must reproduce the same **complete**
report and a supported-under-receiver-context outcome with both native signatures
and historical/current role authorizations. Every timed result is checked again.
Negative/insufficient results or changed input hashes abort the measurement.

## Instrumentation preflight

Both collection modes reject known inherited instrumentation **before** output
creation, executable discovery, input generation or child launches. The policy
checks key presence case-insensitively, including empty strings and `"0"`:
`PYTHONTRACEMALLOC`, `PYTHONMALLOC`, `PYTHONPROFILEIMPORTTIME`, `NODE_V8_COVERAGE`,
`PYTHONDEVMODE`, `PYTHONMALLOCSTATS`, `PYTHONPERFSUPPORT`,
`PYTHON_PERF_JIT_SUPPORT`, `PYTHONDEBUG`, `PYTHONVERBOSE`, `NODE_DEBUG` and
`NODE_DEBUG_NATIVE`. Errors list names only, not environment values.

Unset these variables and restart the driver in a clean Python process.
Deleting startup variables inside an already running interpreter does not undo
its instrumentation: the Python parent also times fresh CLI subprocesses.
Active allocation tracing, trace/profile hooks, diagnostic runtime flags and
options, and registered `sys.monitoring` tools are rejected, not disabled so
that measurement can continue. Clearing a variable is not evidence that an
already initialized allocator or arbitrary external instrumentation is clean.

The existing child-path/options filtering is retained, along with a single
`PYTHONHASHSEED=0` key. One prepared environment snapshot is used for every
measured child, preliminary Node verification and Node version lookup; the
parent environment and required platform variables are preserved.
This is a bounded instrumentation policy, **not hermetic execution** or proof
that every source of runtime/host interference is detected. Report validation
still verifies supplied records; it does not retrospectively authenticate how
a publisher collected them. Timer scopes, native memory queries, cardinalities,
source binding, full-result checks and trigger derivation are unchanged.

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
  Receipt dependency versions come from every sanitized Python measurement
  worker and must agree across all rounds; the driver's inherited Python path
  is not used to identify the libraries in the timed child processes.
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
