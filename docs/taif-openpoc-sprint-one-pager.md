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

This project does not claim to solve alignment or eliminate catastrophic risk. Its narrower contribution is to make one failure mode measurable: **a safety-relevant effect can be omitted while the available trace remains valid**. Identifying and testing the minimum conditions for non-bypassable capture can improve the reliability of agent evaluations, control systems, and audit-based safety arguments.

## Evidence already produced

OpenPoC-01 is merged and reproducible:

- [PR #15 — Separate trace validity from capture completeness](https://github.com/safal207/T-Trace/pull/15)
- [OpenPoC-01 fixture documentation](openpoc-01-selective-omission.md)
- honest, bypass, and gated execution scenarios;
- explicit assurance verdicts rather than a single overloaded `PASS`;
- **11 tests passing**;
- CI, CodeQL, and secret scanning passing.

The key negative result is intentional:

```text
trace_valid        = true
capture_complete   = false
capture_status     = violated
effect_bound       = false
overall_assurance  = insufficient
```

The trace validator is correct to accept the records it received. The assurance failure is inferring complete execution from that structural result.

Independent technical feedback from an append-only transparency-log author and a signed-action-receipt draft author converged on the same boundary: detecting or preventing omission requires evidence at a non-bypassable effect point, not the log alone. A draft author has also offered cross-implementation test vectors for independent comparison.

## Eight-week research scope

### 1. Public adversarial benchmark

Expand OpenPoC into a machine-readable benchmark covering at least:

- recorder bypass / never-recorded action;
- missing, duplicated, and reordered records;
- stale or replayed pre-commitments;
- receipt replay;
- mismatched effect digests;
- truncated and split-view presentations;
- honest-but-unattested capture;
- mandatory-gate capture.

Each vector will have explicit expected verdicts across separate dimensions:

- `trace_valid`;
- `record_integrity`;
- `capture_status`;
- `effect_bound`;
- `overall_assurance`.

### 2. Cross-implementation validation

Run external signed-action-receipt test vectors against T-Trace/OpenPoC and publish an exact compatibility matrix:

- `agree`;
- `disagree`;
- `unsupported`;
- interpretation notes kept separate from test results.

### 3. One external evidence-format adapter

Implement and document an adapter for at least one current signed-receipt or transparency-log format. The goal is composability, not replacement: external formats protect receipt integrity; T-Trace/OpenPoC evaluates causal projection and assurance boundaries.

### 4. Deployment trust model

Specify what must be independently justified before a system may claim capture completeness, including:

- all relevant effects traverse the gate;
- direct resource access is disabled;
- recorder and gate identities are authenticated;
- pre-commitments and receipts resist forgery and replay;
- configuration changes are auditable.

No production TEE, PKI, blockchain, or universal standard is promised within this sprint.

### 5. External technical review and public report

Invite focused review from researchers and implementers already working on evaluation integrity, action receipts, transparency logs, and agent assurance. Publish corrections, negative results, and unresolved assumptions rather than converting feedback into endorsements.

## Deliverables

1. A public benchmark with at least **12 adversarial vectors** and deterministic expected verdicts.
2. A cross-implementation compatibility report against a second receipt implementation or draft vector set.
3. One external evidence-format adapter.
4. A documented L1–L4 assurance model:
   - L1: trace validity;
   - L2: record integrity;
   - L3: capture completeness;
   - L4: independent reproducibility.
5. Reproducible CI across all fixtures and a reviewer-facing final report.
6. A concise integration guide for evaluation and agent-control developers.

## Success criteria

The sprint succeeds if:

- the benchmark reliably distinguishes valid traces from justified completeness claims;
- bypass cases remain structurally valid but cannot receive a complete-assurance verdict;
- mandatory-gate cases block effects lacking required evidence;
- at least two implementations agree on shared test-vector outcomes, or disagreements are precisely isolated;
- all claims include explicit trust assumptions and non-claims;
- all public tests and security checks pass in CI.

A useful negative result also counts as success: if a proposed mechanism cannot establish capture completeness, the benchmark should demonstrate that limitation reproducibly.

## Budget

- **USD 12,000** — research and implementation;
- **USD 3,000** — external implementation/reviewer support where appropriate;
- **USD 3,000** — test infrastructure, compute, and integration environments;
- **USD 2,000** — documentation, release work, and contingency.

## Funding decision requested

Would TAIF consider this an appropriate **8-week, USD 20,000 technical-safety exploration grant**, or should it first be submitted through the standard application route in a different format?
