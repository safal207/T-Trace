# T-Trace / OpenPoC — Grant Evidence Package

**Status:** reviewer-facing evidence package  
**Applicant:** Aleksei Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC  
**Repository:** https://github.com/safal207/T-Trace

## One-sentence claim

T-Trace/OpenPoC is an open protocol and executable benchmark that separates **trace validity**, **record integrity**, **capture completeness**, and **independent reproducibility** instead of collapsing them into one overloaded `PASS` result.

## Core research question

> What evidence is required to distinguish a structurally valid AI-agent trace from a complete and independently checkable account of all safety-relevant effects?

The central failure mode is selective omission: a real effect may occur outside the recorder while the shorter presented trace remains internally valid.

```text
valid presented trace
        ≠
all created records are unchanged
        ≠
every real effect entered the evidence path
        ≠
the claimed outcome was independently reproduced
```

## Reviewer path

### 1. Validate the base T-Trace protocol

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
```

Expected result:

```text
PASS examples/minimal.ttrace.jsonl (3 records)
```

### 2. Reproduce OpenPoC-01 selective omission

```bash
python -m openpoc.verify_assurance \
  examples/openpoc-01/bypass.scenario.json
```

Expected assurance boundary:

```text
trace_valid        = true
capture_complete   = false
capture_status     = violated
effect_bound       = false
overall_assurance  = insufficient
```

The trace validator is correct to accept the records it received. The unsafe inference is treating structural validity as proof of complete execution.

### 3. Reproduce OpenPoC-02 claim-scoped replay

```bash
python -m openpoc.verify_reproducibility \
  examples/openpoc-02/incomplete-but-reproducible.scenario.json
```

Expected boundary:

```text
reproduction_status   = supported-under-stated-assumptions
capture_status        = violated
record_integrity_status = assumed-valid-for-boundary-test
claim_verdict         = violated
missing_effect_ids    = [effect-hidden]
```

The supplied computation is reproducible. The broader claim about all
external effects is still false because the bound input is incomplete.

### 4. Review independent signed-receipt interoperability

Original `-00` evidence:

- [13/13 compatibility report](governex-action-receipts-compatibility.md)
- [independent verifier](../openpoc/action_receipt_compat.py)
- [pinned workflow](../.github/workflows/governex-action-receipts.yml)
- [merged PR #18](https://github.com/safal207/T-Trace/pull/18)

Forthcoming `-01` vector-profile evidence:

- [18/18 compatibility report](governex-action-receipts-v01-compatibility.md)
- [capture-side review](governex-action-receipts-v01-capture-review.md)
- [independent verifier](../openpoc/action_receipt_compat_v01.py)
- [pinned workflow](../.github/workflows/governex-action-receipts-v01.yml)
- [merged PR #23](https://github.com/safal207/T-Trace/pull/23)

### 5. Run the repository test suite

```bash
pip install -e .[dev]
python -m pytest -q
```

Historical result on the Interop-02 merge path:

```text
49 passed
```

That count is a baseline for the historical commit, not evidence about a newer
head. Use the CI run for the exact commit under review for the current result.

## Current evidence matrix

| Evidence | Reviewer question | Result |
|---|---|---|
| Base protocol and schema | Is the trace format machine-checkable? | Implemented |
| Reference validator | Can the canonical trace be checked locally? | PASS |
| OpenPoC-01 | Can a hidden effect coexist with a valid presented trace? | Reproduced |
| OpenPoC-02 | Can bound replay succeed while a broader capture claim fails? | Reproduced |
| Assurance model | Are structural validity and capture completeness separated? | Implemented |
| Governex `-00` interoperability | Does an independent verifier match the original public suite without shared verifier code? | **13/13 AGREE** |
| Governex `-01` interoperability | Does an independent verifier match repetition, ordering, and signed-head outcomes? | **18/18 AGREE** |
| Focused `-01` regression tests | Are new checks covered locally? | **7 passed** |
| Full repository tests | Do existing protocol and profile tests remain green? | Verify on exact-head CI |
| Original `-00` pinned workflow | Does the stable earlier evidence remain reproducible? | PASS |
| New `-01` pinned workflow | Is the new profile reproducible at a fixed upstream commit? | PASS |
| CI / CodeQL / secret scan | Are quality and baseline security checks green? | PASS |
| External public reference | Does the upstream vector repository link the independent evidence? | Yes |
| Planned RFC 7942 credit | Has the draft author confirmed named implementation-status credit? | Yes, for the forthcoming `-01` revision |

## Independent interoperability result

### Original `-00` profile

Pinned upstream commit:

```text
65836f4e1ecb96ff22e8b4ab6a7c086532ce564c
```

Result:

```text
13/13 AGREE
0 DISAGREE
0 UNSUPPORTED
```

### Forthcoming `-01` vector profile

Pinned upstream commit:

```text
6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a
```

Result:

```text
18/18 AGREE
0 DISAGREE
0 UNSUPPORTED
```

The 18 checks comprise 16 receipt-log vectors and 2 signed-head checks. Important cases include:

- repeated `step_id` with valid signatures and intact raw-octet linkage;
- signed `seq` gap versus signed `seq` reuse/regression;
- a signed head assertion that matches the complete log and rejects the truncated presentation.

The T-Trace/OpenPoC verifier does not import or execute the upstream verifier. It independently reconstructs signed bytes, verifies Ed25519 signatures, checks exact raw-octet linkage, enforces identifier uniqueness, evaluates signed sequence rules, and verifies the domain-separated head assertion.

## External technical significance

The Governex vector repository publicly links the original T-Trace/OpenPoC compatibility report, verifier, pinned workflow, and review PR as an independent implementation.

The draft author confirmed that the forthcoming `-01` RFC 7942 Implementation Status section will credit:

> **Aleksei Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC**

Technical feedback from the T-Trace/OpenPoC review informed the new:

- repeated-`step_id` vector;
- signed-`seq` gap vector;
- signed-`seq` repeat/regression vector;
- external signed-head assertion pair.

This is evidence of independent interoperability and useful threat-boundary review. It is not co-authorship, IETF adoption, or endorsement.

## What the current results prove

The current artifacts support these claims:

- presented T-Trace records can be checked for structural and causal validity;
- a selective-omission bypass can leave the presented trace valid while overall assurance remains insufficient;
- a third party can reproduce or falsify a bound relation without treating successful replay as proof of input completeness;
- independently implemented signed-receipt verifiers can agree on canonical signing, signature validity, exact raw-octet linkage, identifier repetition, signed sequence anomalies, and signed-head consistency;
- stable pinned CI can reproduce both the earlier and newer interoperability profiles;
- assurance boundaries can be documented without converting them into product guarantees.

## What the current results do not prove

T-Trace/OpenPoC does **not** currently prove:

- that every real-world action entered the receipt path;
- that a recorder or gate was physically or cryptographically non-bypassable in production;
- that a fresh `step_id` and valid next `seq` represent a unique real-world effect;
- that a signed head is the latest head or that the signer did not equivocate;
- that the draft is correct merely because implementations agree;
- that successful replay over bound inputs proves those inputs contain every relevant external effect;
- production compliance, formal certification, or zero vulnerabilities.

## Assurance dimensions

The L1-L4 labels are names for separate questions, not a monotonic ladder.

| Level | Question | Current artifact |
|---|---|---|
| **L1 — Trace validity** | Are presented records structurally and causally valid? | Base T-Trace validator |
| **L2 — Record integrity** | Were created records altered, reordered, duplicated, or truncated relative to external state? | Governex interoperability profiles |
| **L3 — Capture completeness** | Did every relevant effect have to pass through the evidence path? | OpenPoC-01 boundary and gated fixture assumptions |
| **L4 — Independent reproducibility** | Can a third party reproduce or falsify the claimed outcome? | OpenPoC-02 bound replay fixtures |

## Why this is grant-relevant

Monitoring, control, evaluation, and incident-review systems are increasingly part of safety cases for autonomous agents. If those systems treat a valid trace as proof of complete execution, an agent or operator may perform a dangerous action outside the capture boundary while retaining a green audit result.

T-Trace/OpenPoC makes this failure mode measurable and provides a path toward testing the minimum evidence needed for stronger claims.

```text
false assurance in audit/control layers
                ↓
explicit adversarial fixture
                ↓
separate multidimensional verdicts
                ↓
reproducible trust assumptions and failure boundaries
```

## Eight-week funding scope

The proposed sprint requests **USD 20,000 for 8 weeks** to deliver:

1. at least 12 additional adversarial assurance vectors;
2. continued reproducibility of the 13/13 `-00` and 18/18 `-01` pinned results;
3. one versioned external evidence-format adapter into a T-Trace causal projection;
4. tested trust assumptions for non-bypassable capture, effect identity, head freshness, and anti-equivocation;
5. OpenPoC-02 for independent replay recipes and environment binding;
6. external technical review, an integration guide, and a public final report.

See:

- [TAIF one-page proposal](taif-openpoc-sprint-one-pager.md)
- [TAIF application answer pack](taif-application-answer-pack.md)

## Current strongest positioning

Use this formulation in applications and reviewer conversations:

> T-Trace/OpenPoC is an open benchmark and verification layer for distinguishing a valid AI-agent trace from justified evidence of complete capture and independently reproducible outcomes. It already demonstrates a selective-omission bypass, preserves separate assurance verdicts, and independently matches two pinned Governex signed-receipt profiles: 13/13 checks for `-00` and 18/18 checks for the forthcoming `-01` vector profile.

## Short version

```text
A valid trace proves what is true about the records presented.
It does not automatically prove that every real-world effect was recorded.
```
