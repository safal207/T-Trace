# Reviewer path: run, interpret, and bound the result

This is the entry point for reviewing the implemented T-Trace/OpenPoC path.
The goal is to check a stated claim from supplied evidence, not to inherit a
producer's unconditional `verified` label.

## 1. Prepare the checkout

From the repository root, record the revision and install the development
dependencies in an isolated Python environment:

```bash
git rev-parse HEAD
python -m pip install -e ".[dev]"
```

The package declares Python 3.9 or later; the current CI uses Python 3.11.
Keep the actual Python version and dependency versions with your result. A
successful run on one environment is not a check of every supported runtime.

For a non-editable wheel installation, use the [installed verifier
guide](installed-verifiers.md). Its isolated packaging gate runs outside the
checkout; the following examples assume you also have the fixture inputs.

For the selected external Asqav fixtures, use the [frozen source-package
guide](asqav-frozen-package.md) to acquire original bytes once and verify them
later using separately accepted receiver pins. It retains the same receipt verifier.

Installation and fetching external fixtures require network access. The local
examples below use committed fixture data after installation; they do not
execute real external actions.

## 2. Check a presented trace, then its capture claim

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
python -m openpoc.verify_assurance examples/openpoc-01/bypass.scenario.json
```

The first command should print `PASS ... (3 records)`. For the second, inspect
the JSON fields rather than treating a successful process exit as assurance:

```text
trace_valid        = true
capture_status     = violated
effect_bound       = false
overall_assurance  = insufficient
```

The scenario's separate effect inventory exposes the omitted effect. The
presented trace alone does not discover it. A zero exit code means the fixture
evaluation completed and matched its declared expectations; it can accompany
an intentionally insufficient assurance result.

Read: [OpenPoC-01](openpoc-01-selective-omission.md).

## 3. Separate reproducibility from input completeness

```bash
python -m openpoc.verify_reproducibility examples/openpoc-02/complete-replay.scenario.json
python -m openpoc.verify_reproducibility examples/openpoc-02/incomplete-but-reproducible.scenario.json
```

The complete fixture has `claim_verdict=supported-under-stated-assumptions`.
For the incomplete fixture, expect:

```text
relation_satisfied       = true
reproduction_status     = supported-under-stated-assumptions
capture_status          = violated
record_integrity_status = assumed-valid-for-boundary-test
claim_verdict           = violated
```

The declared computation reproduces over its exact input. That does not make
the input complete. The attestation/transparency markers here are fixture
assumptions, not real signature or transparency-service checks. A required
record-integrity claim remains insufficient without a real evidence adapter.

Read: [OpenPoC-02](openpoc-02-independent-reproducibility.md).

## 4. Review external receipts

These are separate, bounded compatibility subjects. Do not add their counts
into a score for general assurance or coverage of either upstream system.

| Subject | Pinned upstream commit | Committed result | Evidence |
|---|---|---|---|
| Governex `-00` | `65836f4e1ecb96ff22e8b4ab6a7c086532ce564c` | 13/13 AGREE | [Report](governex-action-receipts-compatibility.md), [workflow](../.github/workflows/governex-action-receipts.yml) |
| Governex `-01` | `6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a` | 18/18 AGREE: 16 receipt-log vectors and 2 signed-head checks | [Report](governex-action-receipts-v01-compatibility.md), [workflow](../.github/workflows/governex-action-receipts-v01.yml) |
| Asqav 14–16 | `17c814f9e2e51f005faa707d44adec0316534da8` | 3/3 AGREE | [Report](asqav-capture-compatibility.md), [workflow](../.github/workflows/asqav-capture-compatibility.yml) |

Each verifier reads upstream data without importing or executing the upstream
verifier. This establishes implementation agreement for the declared corpus,
not correctness of a standard, capture completeness, or external endorsement.

### Reproduce the selected Asqav comparison

Use a new destination for the upstream checkout. The commands below are a
local equivalent of the pinned data checkout in CI:

```bash
git clone --no-checkout https://github.com/jagmarques/asqav-sdk ../asqav-review-inputs
git -C ../asqav-review-inputs -c core.autocrlf=false checkout --detach 17c814f9e2e51f005faa707d44adec0316534da8
git -C ../asqav-review-inputs rev-parse HEAD
git -C ../asqav-review-inputs status --porcelain
python -m openpoc.asqav_capture_compat --vectors-root ../asqav-review-inputs/verifier/conformance-vectors --source-commit 17c814f9e2e51f005faa707d44adec0316534da8
```

Before the last command, require the exact commit above and an empty status
output. Stop if either check differs. The comparison should print `3 vectors:
3 agree, 0 disagree, 0 unsupported`.

The CLI's `--source-commit` is report metadata; it does not authenticate the
directory or independently inspect its Git revision. In the existing workflow,
source binding is supplied by the pinned, clean upstream checkout. A locally
modified directory with the same label is not that evidence. The next
[consolidation step](asqav-verification-consolidation.md) considers frozen inputs
and explicit source binding without maintaining a second default verifier.

These vector keys are test trust material, not a production trust policy. A
valid signed marker authenticates a declaration under the supplied test key;
it does not authenticate a production organization merely because an issuer
name matches. The declaration's real-world cause and the completeness of
external execution still need separate evidence.

## 5. Read the claim map before integrating

### Compare two supplied source snapshots

```bash
python -m openpoc.verify_cross_source examples/openpoc-03/counterpart-omission.scenario.json
python -m openpoc.verify_cross_source examples/openpoc-03/nonfinal-snapshots.scenario.json
python -m openpoc.verify_cross_source examples/openpoc-03/delayed-observation.scenario.json
```

The first and third fixtures report `pairwise_consistency_status=violated`;
the second reports `insufficient-snapshot-finality`. All keep
`global_completeness_status=unproven`. A late-observed record cannot repair a
past cutoff. A successful fixture exit is not a completeness verdict.

Read the [OpenPoC-03 contract](openpoc-03-cross-source-correlation.md) for
the explicit clock/finality assumptions and the distinction between a
missing counterpart, presented digest conflict, and insufficient evidence.

| Question | Implemented evidence | Boundary |
|---|---|---|
| Do the presented records follow the rules? | Base validator | Only supplied records, not every external event |
| Do these supplied receipts authenticate and link? | Pinned Governex/Asqav comparisons | Trust material and supported corpus are explicit inputs |
| Is a selected historical item included, or is a root an extension? | Membership/consistency profiles | Compact verification does not inherit every full-history builder check |
| Was a policy change authorized under the supplied context? | Handoff profiles | Authentication of external authority evidence remains a separate obligation |
| Is this the latest trusted state now? | Not established by root consistency alone | Requires a freshness policy and appropriate external state |
| Were all relevant effects captured? | OpenPoC-01/02 inventory and gate assumptions | Not a proof of a non-bypassable production deployment |
| Can the claimed computation be reproduced? | OpenPoC-02 bound recipe | Does not establish input completeness or broader policy meaning |
| Do two supplied snapshots agree at the audit cutoff? | OpenPoC-03 comparison | Declared clocks, identities, and finality; no authentication or global coverage |

The L1–L4 names in [assurance dimensions](assurance-levels.md) are separate
questions, not a maturity ladder. Authority statements carrying `verified=true`
record an external result; that field cannot grant itself authority. See the
[handoff root-consistency boundary](../spec/witness-policy-handoff-chain-membership-root-consistency-profile-v0.1.md#2-assurance-boundary)
and [authority statements](../spec/witness-policy-handoff-chain-membership-root-consistency-profile-v0.1.md#9-authority-statements).

Historical consistency, current authorization, freshness, and capture
completeness must remain separate when evidence crosses systems or epochs.
The receiver supplies its trust roots and acceptance policy independently of
the producer's package.

## 6. Record a review result

```bash
python -m pytest -q
git diff --check
```

Record the T-Trace commit, whether the checkout was modified, runtime and
dependency versions, exact input revisions, command results, and claim-scoped
verdicts. For hosted verification, record the CI run URL, attempt, and tested
SHA. Local success does not imply hosted checks passed; a prior green run or a
README badge is not evidence for a different revision. The dedicated interop
workflows regenerate reports from pinned external inputs; local unit tests
alone are not a rerun of those external corpora.

## Next, not yet an integration guarantee

OpenPoC-03 supplies bounded cross-source comparison, not a production capture
guarantee. The next integration milestone is one package
checked by another party with explicit inputs, trust assumptions, and audit
cutoff. Offline archival completeness, current freshness, production capture,
and independently operated observers are not promised by this document.
