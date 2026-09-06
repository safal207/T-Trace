# TAIF one-page proposal — Verifiable capture for autonomous agent actions

**Applicant:** Aleksei Safonov  
**Project:** [T-Trace / OpenPoC](https://github.com/safal207/T-Trace)  
**Proposed duration:** 8 weeks  
**Funding request:** **USD 20,000**

**Draft status, refreshed 2026-09-06:** the amount and eight-week duration
remain proposal parameters, not a funded commitment. The application route
and funding availability have not been revalidated. See the [reviewer
path](reviewer-path.md) for the implemented baseline; new work must extend,
not re-count, existing OpenPoC-02 and interoperability results.

## Problem

Agent evaluations, monitoring systems, approval layers, and incident reviews often treat a valid audit trail as evidence that the trail is a complete account of execution. That inference is unsafe.

A capable agent or operator may reach a tool, API, ledger, credential, or other effect-producing resource through a path that bypasses the recorder. The presented trace can remain structurally valid even though a material action is missing. Hash chains, signatures, timestamps, and transparency anchors can protect records that were created; they cannot reveal an action that never entered the evidence path.

The central research question is:

> What evidence is required to distinguish a valid recorded history from a complete account of all safety-relevant effects?

## Why this matters for AI safety and GCR reduction

As agents gain longer horizons, broader tool access, and the ability to operate with limited human supervision, safety cases increasingly depend on monitoring, control, evaluation, and post-incident evidence.

If those systems confuse **trace validity** with **capture completeness**, an agent or operator can perform a dangerous action while still presenting a green audit result. This creates false assurance at exactly the layers intended to provide defence in depth.

This project does not claim to solve alignment or eliminate catastrophic risk. Its narrower contribution is to make one failure mode measurable: **a safety-relevant effect can be omitted while the available trace remains valid**. Testing the minimum conditions for non-bypassable capture can improve the reliability of agent evaluations, control systems, and audit-based safety arguments.

## Evidence already produced

### OpenPoC-01 — selective omission

[PR #15](https://github.com/safal207/T-Trace/pull/15) is merged and reproducible. It contains honest, bypass, and gated execution scenarios and separates structural validity from assurance:

```text
trace_valid        = true
capture_complete   = false
capture_status     = violated
effect_bound       = false
overall_assurance  = insufficient
```

The validator is correct to accept the records it received. The assurance failure is inferring complete execution from that structural result.

### Independent signed-receipt interoperability

T-Trace/OpenPoC now preserves two separately pinned, independently implemented Governex compatibility profiles. Neither verifier imports or executes the upstream verifier.

**Original `-00` suite — [PR #18](https://github.com/safal207/T-Trace/pull/18):**

```text
13/13 AGREE
0 DISAGREE
0 UNSUPPORTED
```

Pinned upstream commit: `65836f4e1ecb96ff22e8b4ab6a7c086532ce564c`  
Evidence: [`-00` compatibility report](governex-action-receipts-compatibility.md)

**Pinned `-01` vector profile — [PR #23](https://github.com/safal207/T-Trace/pull/23):**

```text
18/18 AGREE
0 DISAGREE
0 UNSUPPORTED
```

This covers 16 receipt-log vectors and 2 signed-head checks at upstream commit `6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a`, including:

- repeated `step_id` with valid signatures and intact linkage;
- signed `seq` gap versus signed `seq` reuse/regression;
- a domain-separated signed head that matches the full log and rejects the truncated presentation.

Evidence: [`-01` compatibility report](governex-action-receipts-v01-compatibility.md) · [capture-side review](governex-action-receipts-v01-capture-review.md)

The repository contains focused regressions and pinned report-regeneration
workflows. Check the full suite, interoperability jobs, CodeQL, and secret
scanning for the exact commit under review; historical counts or green runs
do not establish current verification status.

The recorded Governex review includes an upstream public reference and the
draft author's confirmation of planned `-01` RFC 7942 credit for **Aleksei
Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC**. This is
historical review evidence, not a live claim about publication status.
Technical feedback informed the repeated-`step_id`, signed-`seq`, and
signed-head vectors.

The non-claim remains explicit: conformance is interoperability evidence only. It does not prove draft correctness, capture completeness, head-signer non-equivocation, or effect-level anti-replay binding.

### Additional implemented baseline

- **OpenPoC-02:** bound replay fixtures already distinguish reproduction of
  the supplied computation from completeness of its inputs. [Evidence](openpoc-02-independent-reproducibility.md).
- **Asqav 14–16:** **3/3 AGREE** at upstream commit
  `17c814f9e2e51f005faa707d44adec0316534da8`, with independent signature,
  predecessor-link, and signed-marker checks. This does not establish
  production capture completeness or the external cause of a signed gap.
  [Evidence](asqav-capture-compatibility.md).

## Eight-week research scope

### 1. Expand the adversarial assurance benchmark

Add at least **12 new T-Trace/OpenPoC vectors** covering:

- recorder bypass / never-recorded action;
- stale or replayed pre-commitments;
- receipt replay and cross-run substitution;
- fresh-record replay of the same semantic effect;
- mismatched effect digests;
- missing, duplicated, reordered, and truncated records;
- split-view presentations and stale head assertions;
- honest-but-unattested capture;
- mandatory-gate capture and configuration drift.

Each vector will have deterministic expected verdicts across separate dimensions:

- `trace_valid`;
- `record_integrity`;
- `capture_status`;
- `effect_bound`;
- `overall_assurance`.

### 2. Build one external evidence-format adapter

Implement a versioned adapter from a current signed-action-receipt or transparency-log format into a T-Trace causal projection. The goal is composability, not replacement: external formats protect receipt integrity; T-Trace/OpenPoC evaluates causal meaning and assurance boundaries.

### 3. Specify and test the deployment trust model

Define what must be independently justified before a system may claim capture completeness:

- all relevant effects traverse the gate;
- direct resource access is disabled;
- recorder and gate identities are authenticated;
- sequence or pre-commitment allocation occurs before the effect and cannot be bypassed;
- pre-commitments and receipts resist forgery, replay, and cross-run substitution;
- configuration changes are themselves auditable;
- external head state has a freshness and anti-equivocation mechanism.

No production TEE, PKI, blockchain, or universal standard is promised within this sprint.

### 4. Extend OpenPoC-02 — independent reproducibility

The base positive and negative replay-recipe fixtures are already implemented.
Extend them through the selected evidence adapter and an independently run
reviewer path. Define the new artifact/environment cases before counting them
as sprint deliverables; successful replay must still not imply complete input.

### 5. External review and public report

Invite focused review from implementers working on evaluation integrity, action receipts, transparency logs, and agent assurance. Publish corrections, negative results, disagreements, and unresolved assumptions rather than converting feedback into endorsements.

## Deliverables

1. At least **12 additional adversarial assurance vectors** with deterministic verdicts.
2. Continued reproducibility of the existing **13/13 `-00`**, **18/18 `-01`**, and **3/3 selected Asqav** pinned interoperability results.
3. One versioned external evidence-format adapter.
4. A documented and executable L1–L4 assurance model:
   - L1: trace validity;
   - L2: record integrity;
   - L3: capture completeness;
   - L4: independent reproducibility.
5. Extensions to the implemented OpenPoC-02 fixtures through the selected adapter and external reviewer path.
6. Reproducible CI, a reviewer-facing final report, and an integration guide for evaluation and agent-control developers.

## Success criteria

The sprint succeeds if:

- bypass cases remain structurally valid but cannot receive a complete-assurance verdict;
- mandatory-gate cases block effects lacking required evidence;
- fresh-identity replay and cross-run substitution produce separate, correct verdicts;
- the new adapter preserves explicit distinctions between signature validity, chain integrity, capture completeness, effect binding, and reproducibility;
- both pinned Governex profiles and the selected Asqav comparison remain reproducible;
- at least two external implementers review a concrete artifact or compatibility result;
- all claims include explicit trust assumptions and non-claims;
- all public tests and security checks pass in CI.

A useful negative result also counts as success: if a proposed mechanism cannot establish capture completeness or independent reproducibility, the benchmark should demonstrate that limitation reproducibly.

## Budget

- **USD 12,000** — research and implementation;
- **USD 3,000** — external implementation/reviewer support where appropriate;
- **USD 3,000** — test infrastructure, compute, and integration environments;
- **USD 2,000** — documentation, release work, and contingency.

## Funding request

I am requesting an **8-week, USD 20,000 technical-safety exploration grant** through the Transformative AI Fund's standard application route.
