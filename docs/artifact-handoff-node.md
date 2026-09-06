# A second implementation of the selected handoff profile

The standalone [Node verifier](../verifiers/node/artifact-handoff.mjs) implements
only [artifact-handoff/v1](../spec/artifact-handoff-profile-v0.1.md). It does not
import or invoke the Python verifier, OpenPoC comparison, or a producer service.
It needs one `.mjs` file, a Node runtime and saved input bytes. There are no npm
dependencies or installation scripts.

This is implementation diversity, not independent authorship, an independent
organization, a clean-room process, a distinct cryptographic backend, or an
external pilot. Both implementations may depend on OpenSSL beneath their
language APIs. Agreement is bounded evidence, not proof that both cannot share
a contract misunderstanding. The manually specified corpus expectations remain
a separate gate; matching each other alone is insufficient.

## Run without Python

Use the tested [Node.js 24.19.0 release](https://nodejs.org/en/blog/release/v24.19.0)
or revalidate another supported runtime. CI pins this exact version; runtime
acquisition is separate from offline verification. This is a tested-version
record, not a promise that this runtime remains the latest security release.

```sh
node verifiers/node/artifact-handoff.mjs verify /path/to/package \
  --receiver-context /separate/receiver-context.json

node verifiers/node/artifact-handoff.mjs corpus examples/artifact-handoff-v0.1
```

The byte API exports `verifyHandoff(files, receiverContext)`, where every input
file and the context are Node Buffers. It returns the same complete structured
report as Python. The file API is `verifyDirectory(packagePath, contextPath)`.
`HandoffError.code` is the typed invalid-input result. CLI exit 0 means a
successful evaluation, including a negative or insufficient-evidence decision;
it is not unconditional approval. Exit 2 emits an invalid-input JSON report.
Human error wording is implementation-specific; the comparison checks codes.

The Node code implements its own lexical JSON parser, decoded duplicate-key
detection, strict scalar/bound checks, native receipt signed-byte construction,
Ed25519 verification through `node:crypto`, receiver-context validation,
historical/current authority decisions and two-source snapshot projection.
Restricted ASCII identifiers and safe integers are deliberate profile limits;
this is not an arbitrary-JSON canonicalizer or an all-profile T-Trace verifier.

## Reproduce the cross-implementation gate

Python is needed for this comparison harness, **not** for the Node verifier.
Install the first verifier's receipt dependencies as described in the
[handoff guide](artifact-handoff.md), then run:

```sh
node --test verifiers/node/artifact-handoff.test.mjs
python scripts/compare_handoff_implementations.py --node /absolute/path/to/node
```

`--work-root /path/outside/checkout` selects a writable temporary-directory
parent. `--output /path/to/report.json` saves the complete comparison record.
On Windows, use the actual `node.exe` path. The harness:

1. Evaluates every declared case in Python against its hand-written expectations.
2. Copies only the standalone JS file and public corpus outside the checkout.
3. Starts Node with a cleared module/preload environment, an unhelpful PATH,
   and permission-mode reads limited to that copy; subprocess creation is not
   allowed. No first-verifier output is supplied to Node.
4. Checks each Node result against the hand-written expectations and compares
   all report fields, including hashes, trust assumptions, exclusions and
   non-claims; malformed cases must have the same typed error code.
5. Rejects missing/duplicate cases, different corpus hashes, changed report
   members and empty declarations. It never silently skips a missing runtime.

The permission controls are additional execution guardrails, not a claim of an
OS sandbox against arbitrary malicious Node code. Input files must be stable
during review; concurrent filesystem mutation is outside this saved-package
workflow. Receiver context remains externally accepted, not self-authenticated
by its separate file location.

## Recorded evidence

The [machine comparison](artifact-handoff-implementation-comparison.json) records
40/40 agreement on the entire frozen corpus, with a canonical full-report
SHA-256 for each evaluated case and a code for each malformed case. The corpus
and Node source hashes bind the record to the actual inputs and implementation.
It was generated on Windows with Python 3.12.14 and Node 24.19.0; fresh CI
repeats the comparison on Linux with Python 3.11 and Node 24.19.0.

The local Node controls passed 47 tests, with one Windows symlink-creation
privilege skip. Linux CI runs that same control without the Windows restriction.
Tests cover strict parsing, signed bytes, signature changes, context ambiguity,
limits, path separation and non-vacuous corpus coverage. A separate Python test
protects the comparison gate against incomplete reports and false agreement.

This closes only the second-implementation gate when merged and fresh CI is
confirmed. External participant decisions, first-time reviewer timing,
performance budgets, final boundary audit and release-candidate readiness are
separate roadmap requirements.
