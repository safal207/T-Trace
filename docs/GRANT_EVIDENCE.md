# T-Trace / OpenPoC — Grant Evidence Package

**Status:** reviewer-facing evidence package  
**Applicant:** Aleksei Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC  
**Repository:** https://github.com/safal207/T-Trace

Evidence inventory refreshed on 2026-09-06 against main
`3126937608ab5c8164ace103f3cfb08e2ad852b6`. Start with the
[reviewer path](reviewer-path.md) for commands and claim boundaries. This is
an inventory of committed evidence, not a live CI attestation or confirmation
of funding availability.

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

Pinned `-01` vector-profile evidence:

- [18/18 compatibility report](governex-action-receipts-v01-compatibility.md)
- [capture-side review](governex-action-receipts-v01-capture-review.md)
- [independent verifier](../openpoc/action_receipt_compat_v01.py)
- [pinned workflow](../.github/workflows/governex-action-receipts-v01.yml)
- [merged PR #23](https://github.com/safal207/T-Trace/pull/23)

### 5. Review selected Asqav omission/recovery evidence

- [3/3 compatibility report](asqav-capture-compatibility.md)
- [independent verifier](../openpoc/asqav_capture_compat.py)
- [pinned workflow](../.github/workflows/asqav-capture-compatibility.yml)
- [merged PR #38](https://github.com/safal207/T-Trace/pull/38)

The subject is vectors 14, 15, and 16 at upstream commit
`17c814f9e2e51f005faa707d44adec0316534da8`. Verified signatures, links, and
signed markers do not independently establish the scenario's real-world
cause or production non-bypassability. The [reviewer path](reviewer-path.md#4-review-external-receipts)
documents reproduction and source-binding limits.

### 6. Run the repository test suite

```bash
pip install -e .[dev]
python -m pytest -q
```

Record the exact T-Trace revision, environment, test result, and hosted CI run
and attempt for the commit under review. Historical test counts and earlier
green workflows are not verification of a newer head. The full local suite
does not replace report regeneration against pinned external inputs.

## Committed evidence matrix

Results below describe the linked fixture/corpus artifacts. Current CI and
security-check status must be read for the exact revision under review.

| Evidence | Reviewer question | Result |
|---|---|---|
| Base protocol and schema | Is the trace format machine-checkable? | Implemented |
| Reference validator | Can the canonical trace be checked locally? | PASS |
| OpenPoC-01 | Can a hidden effect coexist with a valid presented trace? | Reproduced |
| OpenPoC-02 | Can bound replay succeed while a broader capture claim fails? | Reproduced |
| Assurance model | Are structural validity and capture completeness separated? | Implemented |
| Governex `-00` interoperability | Does an independent verifier match the original public suite without shared verifier code? | **13/13 AGREE** |
| Governex `-01` interoperability | Does an independent verifier match repetition, ordering, and signed-head outcomes? | **18/18 AGREE** |
| Asqav 14–16 interoperability | Do the selected omission/recovery vectors agree? | **3/3 AGREE**, limited to this pinned subject |
| Focused interoperability regressions | Are the receipt boundaries covered by tests? | Tests committed; rerun for the selected revision |
| Full repository tests | Do existing protocol and profile tests remain green? | Verify on exact-head CI |
| Original `-00` pinned workflow | Does the stable earlier evidence remain reproducible? | Verify on exact-head CI |
| `-01` pinned workflow | Is the profile reproducible at a fixed upstream commit? | Verify on exact-head CI |
| Asqav pinned workflow | Do both reports regenerate from exact external inputs? | Verify on exact-head CI |
| CI / CodeQL / secret scan | Are quality and baseline security checks green? | Verify on exact-head CI |
| External public reference | Does the upstream vector repository link the independent evidence? | Yes |
| Planned RFC 7942 credit | Was named implementation-status credit confirmed during review? | Historical confirmation; not a live publication-status check |

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

### Pinned `-01` vector profile

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

At the time of the Interop-02 review, the draft author confirmed planned
`-01` RFC 7942 Implementation Status credit for:

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
2. continued reproducibility of the 13/13 `-00`, 18/18 `-01`, and 3/3 selected Asqav pinned results;
3. one versioned external evidence-format adapter into a T-Trace causal projection;
4. tested trust assumptions for non-bypassable capture, effect identity, head freshness, and anti-equivocation;
5. extensions to the already implemented OpenPoC-02 replay and environment-binding fixtures;
6. external technical review, an integration guide, and a public final report.

See:

- [TAIF one-page proposal](taif-openpoc-sprint-one-pager.md)
- [TAIF application answer pack](taif-application-answer-pack.md)

This funding scope is a draft proposal, not a funded commitment. OpenPoC-02
already exists, and the three-vector Asqav comparison is part of the baseline.
Reconcile any additional deliverables with that baseline before submitting;
the budget and application route have not been revalidated here.

## Current strongest positioning

Use this formulation in applications and reviewer conversations:

> T-Trace/OpenPoC is an open benchmark and verification layer for distinguishing a valid AI-agent trace from justified evidence of complete capture and independently reproducible outcomes. Its committed evidence includes OpenPoC-01/02, separate assurance verdicts, two pinned Governex comparisons (13/13 `-00` and 18/18 `-01`), and a three-vector Asqav omission/recovery comparison (3/3). These are bounded fixture and interoperability results, not production capture or deployment guarantees.

## Short version

```text
A valid trace proves what is true about the records presented.
It does not automatically prove that every real-world effect was recorded.
```
