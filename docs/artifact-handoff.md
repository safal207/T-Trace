# Review a controlled artifact handoff across time

The selected profile also has a [standalone Node implementation](artifact-handoff-node.md)
with full-report comparison across every frozen corpus case. Python is not
needed to run that verifier.

This path answers one bounded question: do the authenticated declarations in
these supplied snapshots support transfer of this expected artifact by the
cutoff, under the receiver's chosen trust context? It separately reports whether
the signers match current policy. It does not turn either answer into permission
to execute a new action.

The [selected contract](../spec/artifact-handoff-profile-v0.1.md) reuses the
existing Governex -01 signed-byte adapter and OpenPoC-03 comparison. It adds no
new signature envelope, witness network or implicit authority grant.

## Start with a controlled example

Install T-Trace with its `receipts` extra in an isolated environment. Development
checkouts can use `python -m pip install -e '.[dev]'`; for a recipient installation
use a built wheel and separately acquired dependencies as explained in the
[installed-verifier guide](installed-verifiers.md). Network acquisition is a
separate step from offline verification.

From the checkout, run the demo with a new output directory:

```bash
python -m openpoc.artifact_handoff_demo /path/to/new-handoff-demo
```

The sender writes and reads a harmless public text artifact. The file is actually
copied to the receiver, which separately reads and signs its bytes. Original
receipts and the artifact are saved in `package/`; independently selected inputs
and machine/human reports are in `reviewer/`. Existing output is never overwritten.

Both keys are deliberately public test keys. Every time value and the receiver
context are synthetic fixture inputs, not an external time authority. The demo
notice states these limitations. Never use its keys/context as production trust.

```text
sender/ artifact + sender receipt
    → controlled file copy
receiver/ artifact + receiver receipt
    → package/ original bytes + transport manifest
reviewer/ separately accepted context
    → offline verifier → report.json + report.md
```

The verifier itself neither copies the artifact to an external service nor
replays any effect. It reads bounded local inputs and produces a report.

The matching fixture's [machine report](artifact-handoff-report.json) and
[human report](artifact-handoff-report.md) show the actual output dimensions.
They are synthetic fixture results, not evidence of a production deployment.

## Verify the saved package

```bash
ttrace-handoff /path/to/package --receiver-context /separate/context.json
ttrace-handoff /path/to/package --receiver-context /separate/context.json --format markdown
```

Equivalent module invocation:

```bash
python -m openpoc.verify_artifact_handoff /path/to/package \
  --receiver-context /separate/context.json
```

Input context must be outside the package. Its provenance still needs independent
receiver acceptance: a filesystem path cannot prove that the sender did not
invent a policy or observation time. Report hashes bind the exact context and
manifest used. Use controlled local storage; this is not isolation against a
concurrent hostile process mutating the filesystem.

Exit code `0` means evaluation completed, including negative or insufficient
results. Inspect `handoff_at_cutoff`, both receipt authority fields, and
`cross_source.status`. Invalid input/dependency failures use exit code `2` with
an explicit `error.code`. Do not treat process success as universal approval.

The public byte API is `ttrace.verify_artifact_handoff(files, receiver_context)`.
`files` maps exact package filenames to original bytes; receiver context is also
bytes. `HandoffValidationError` exposes a typed `code`. Caller code is responsible
for acquiring/accepting the external trust context. Base T-Trace validation and
the existing receipt interoperability reports are not silently changed.

## Read the dimensions, not a green badge

| Situation | Historical handoff/authority | Current authority |
|---|---|---|
| Matching final evidence and fresh accepted context | Supported under receiver context | Authorized only if current epoch/key/scope match |
| Key or policy rotates after accepted observation | Historical result can remain supported | Old epoch/key is not current permission |
| Revocation after accepted observation | Prior authority remains assessable | Denied once revocation is effective |
| Compromise at/before first accepted observation | Indeterminate; signer clock cannot backdate it into safety | Not authorized |
| Receipt arrives after cutoff | Does not repair the earlier snapshot | Checked separately |
| Missing observation/archive/key-status freshness | Insufficient evidence | Never inferred from old signatures |
| Missing current-policy freshness | Historical result may remain supported with fresh key status | Insufficient current-policy evidence |
| Signed conflicting artifact | Visible conflict under authenticated source binding | Does not authorize the expected handoff |
| Invalid-signature claim | Not an authenticated conflict or accepted counterpart | Not evaluable from that receipt |

Historical authority here is assessed **at the separately accepted observation
time**, not at an independently proved execution/signing instant. The receipt's
own clock remains a declaration. Matching artifact hashes do not independently
prove truthful source behavior or every real-world effect.

## Frozen decision corpus

The [corpus manifest](../examples/artifact-handoff-v0.1/corpus.json) declares 40
cases with hand-written expected dimensions or error codes. It contains 11
distinct original-byte packages, plus separate contexts. Case IDs cover policy
and key rotation, expiry/revocation/compromise, missing archives/observations,
fresh/stale/future status, delayed delivery, inclusive cutoff, nonfinal snapshots,
authenticated and unauthenticated conflicts, untrusted keys, strict booleans,
duplicate JSON keys, number bounds, unknown versions and raw byte drift.

```bash
python -m openpoc.artifact_handoff_corpus verify examples/artifact-handoff-v0.1
```

The generator is deterministic, refuses an existing destination, and does not
derive expected decisions by asking the verifier. Regression tests regenerate
the corpus and compare every file's bytes. Additional API/CLI tests cover the
selected type, cardinality, path, signature, time and resource boundaries.

The same complete declared corpus is now checked by the separate
[Node implementation](artifact-handoff-node.md), with full report and typed-error
comparison. This is implementation diversity, not an external pilot. A public
test key never becomes a production trust root.

## Local installation verification (2026-09-06)

The full suite passed 522 tests; two Windows symlink-creation checks were skipped
for local permissions and remain enabled in Linux CI. Wheel SHA-256
`499b1bf8bcc0e665f5b4cff022f3ed99a5b8e6f0146f5b9391aa6ab04496c45b` was installed
into a fresh Python 3.12.14 environment using only previously acquired local
wheels: cryptography 46.0.4, cffi 2.1.1 and pycparser 3.0. All 40 corpus cases
agreed outside the checkout, module locations were checked, the console and
module reports matched, and the human report was exercised. The dependency-free
core installation gate also retained its seven module and four console results.

CI repeats the installed-handoff gate on Linux. The build/acquisition stage may
use the network; the separate recipient installation and verification stage uses
`--no-index --no-deps` and local wheels. This is an internally operated portability
check, separate from the second-implementation and external-user gates.

## Disclosure inventory and remaining gates

The example contains only public synthetic artifact text, public fixture keys,
synthetic identifiers/times, policies, receipt signatures, file hashes and expected
outcomes. It includes no user production traces, private keys with real authority,
credentials, user conversations or personal data. Do not substitute real data
without a new disclosure review and the relevant participant's permission.

Still separate from this internal controlled workflow: a second implementation,
measured verification budgets, an externally operated pilot with a useful decision,
a new reviewer's timed setup, and a supported release candidate. These are not
established by running two processes, passing CI, or merging this implementation.
Global capture completeness, production non-bypassability and real-world effect
truth remain unproven.
