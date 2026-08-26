# TAIF one-page proposal — Verifiable capture for autonomous agent actions

**Applicant:** Aleksei Safonov  
**Project:** [T-Trace / OpenPoC](https://github.com/safal207/T-Trace)  
**Proposed duration:** 8 weeks  
**Funding request:** **USD 20,000**

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

**Forthcoming `-01` vector profile — [PR #23](https://github.com/safal207/T-Trace/pull/23):**

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

Current verification evidence:

- **49 repository tests passing**;
- **7 focused `-01` interoperability tests passing**;
- original `-00` and new `-01` pinned interoperability workflows passing;
- deterministic report regeneration passing;
- CI, CodeQL, and secret scanning passing.

The Governex vector repository publicly links the independent T-Trace/OpenPoC evidence. The draft author confirmed that the forthcoming `-01` RFC 7942 Implementation Status section will name **Aleksei Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC**. Technical feedback from this review informed the repeated-`step_id`, signed-`seq`, and signed-head vectors.

The non-claim remains explicit: conformance is interoperability evidence only. It does not prove draft correctness, capture completeness, head-signer non-equivocation, or effect-level anti-replay binding.

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

### 4. OpenPoC-02 — independent reproducibility

Test the difference between a prover supplying a trace and a prover supplying a trace plus the recipe, inputs, versions, and environment evidence required for a third party to reproduce or falsify the claimed transition.

### 5. External review and public report

Invite focused review from implementers working on evaluation integrity, action receipts, transparency logs, and agent assurance. Publish corrections, negative results, disagreements, and unresolved assumptions rather than converting feedback into endorsements.

## Deliverables

1. At least **12 additional adversarial assurance vectors** with deterministic verdicts.
2. Continued reproducibility of the existing **13/13 `-00`** and **18/18 `-01`** pinned interoperability results.
3. One versioned external evidence-format adapter.
4. A documented and executable L1–L4 assurance model:
   - L1: trace validity;
   - L2: record integrity;
   - L3: capture completeness;
   - L4: independent reproducibility.
5. OpenPoC-02 with positive and negative replay-recipe fixtures.
6. Reproducible CI, a reviewer-facing final report, and an integration guide for evaluation and agent-control developers.

## Success criteria

The sprint succeeds if:

- bypass cases remain structurally valid but cannot receive a complete-assurance verdict;
- mandatory-gate cases block effects lacking required evidence;
- fresh-identity replay and cross-run substitution produce separate, correct verdicts;
- the new adapter preserves explicit distinctions between signature validity, chain integrity, capture completeness, effect binding, and reproducibility;
- both pinned Governex compatibility profiles remain reproducible;
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
