# TAIF application answer pack — T-Trace / OpenPoC

This document is a copy-ready source for the EA Funds standard application form. Adjust field lengths to the form and complete the personal fields at the end before submission.

## Core details

**Fund**  
Transformative AI Fund

**Project title**  
Verifiable Capture for Autonomous Agent Actions — T-Trace / OpenPoC

**Applicant**  
Aleksei Safonov

**Applicant type**  
Individual / independent open-source researcher and QA engineer

**Funding requested**  
USD 20,000

**Project duration**  
8 weeks

**Project repository**  
https://github.com/safal207/T-Trace

**Full proposal**  
https://github.com/safal207/T-Trace/blob/main/docs/taif-openpoc-sprint-one-pager.md

## One-sentence summary

Build an open adversarial benchmark and interoperability layer that distinguishes a structurally valid AI-agent trace from justified evidence that every safety-relevant effect was actually captured and can be independently checked.

## Short project description

AI-agent evaluations, monitoring systems, approval layers, and incident reviews often treat a valid audit trail as evidence that the trail is a complete account of execution. That inference can fail: an agent or operator may reach a tool, API, ledger, credential, or other effect-producing resource through a path that bypasses the recorder, while the shorter presented trace remains structurally valid.

T-Trace/OpenPoC makes this failure mode executable. OpenPoC-01 separates `trace_valid` from `capture_complete`. Two separately pinned, independently implemented receipt verifiers now match all **13/13 Governex `-00` vectors** and **18/18 Governex `-01` checks** without importing or executing the upstream verifier. The proposed 8-week sprint will expand the adversarial benchmark, build one external evidence-format adapter, specify the deployment trust model for non-bypassable capture, and add an independent-reproducibility fixture.

## Problem and neglectedness

As agents gain longer horizons and broader tool access, safety cases increasingly rely on logs, monitoring, control systems, evaluations, and post-incident evidence. Existing integrity mechanisms can prove properties of records that were created, but they cannot by themselves reveal an action that never entered the evidence path.

This creates a narrow but important gap between:

1. **trace validity** — the presented records satisfy structural rules;
2. **record integrity** — created records were not altered or reordered;
3. **capture completeness** — every relevant real-world effect had to enter the evidence path;
4. **independent reproducibility** — a third party can reproduce or falsify the claimed transition from bound inputs, versions, and environment evidence.

The project focuses on making these assurance levels measurable rather than collapsing them into one overloaded `PASS` result.

## Theory of change

**Inputs**

- eight weeks of focused research and implementation;
- public signed-receipt conformance vectors;
- external technical feedback from receipt, transparency-log, and assurance implementers;
- open-source CI and security tooling.

**Activities**

- build adversarial vectors for bypass, replay, substitution, truncation, split view, stale head state, and gate failure;
- implement an adapter from one external signed-receipt or transparency-log format;
- specify trust assumptions required for non-bypassable capture;
- build independent-reproducibility fixtures;
- publish exact agreements, disagreements, negative results, and non-claims.

**Outputs**

- a public benchmark with deterministic multidimensional verdicts;
- a versioned evidence-format adapter;
- an executable L1–L4 assurance model;
- compatibility reports and an integration guide;
- reproducible CI and a reviewer-facing final report.

**Intermediate outcome**

Evaluation, control, and monitoring developers can test whether their systems are merely validating available records or are justified in claiming complete capture and reproducible outcomes.

**GCR relevance**

A highly capable autonomous agent or operator that can perform dangerous tool actions outside the capture boundary may preserve a green audit result and defeat layers intended to provide defence in depth. Making this failure mode explicit and testable can reduce false assurance in agent evaluations, control systems, and audit-based safety arguments.

The project does not claim to solve alignment or eliminate catastrophic risk. It targets one concrete evidence failure mode that becomes more consequential as agent autonomy and access increase.

## Evidence and progress to date

### OpenPoC-01

Merged PR:
https://github.com/safal207/T-Trace/pull/15

The bypass fixture intentionally produces:

```text
trace_valid        = true
capture_complete   = false
capture_status     = violated
effect_bound       = false
overall_assurance  = insufficient
```

This demonstrates that the validator may correctly accept the records presented while the broader assurance claim remains unsupported.

### Independent conformance — original `-00` suite

Merged PR:
https://github.com/safal207/T-Trace/pull/18

Compatibility report:
https://github.com/safal207/T-Trace/blob/main/docs/governex-action-receipts-compatibility.md

Against 13 public conformance vectors for `draft-sahu-agent-action-receipts-00`, pinned at upstream commit `65836f4e1ecb96ff22e8b4ab6a7c086532ce564c`:

```text
13/13 AGREE
0 DISAGREE
0 UNSUPPORTED
```

### Independent conformance — forthcoming `-01` vector profile

Merged PR:
https://github.com/safal207/T-Trace/pull/23

Compatibility report:
https://github.com/safal207/T-Trace/blob/main/docs/governex-action-receipts-v01-compatibility.md

Capture-side review:
https://github.com/safal207/T-Trace/blob/main/docs/governex-action-receipts-v01-capture-review.md

Against the updated public suite pinned at upstream commit `6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a`:

```text
18/18 AGREE
0 DISAGREE
0 UNSUPPORTED
```

The 18 checks comprise 16 receipt-log vectors and 2 signed-head checks. They include repeated `step_id`, signed `seq` gap/reuse, and a signed external head that accepts the complete log and rejects the truncated presentation.

Both T-Trace/OpenPoC verifiers are separately implemented. They reconstruct signed bytes, validate Ed25519 signatures, and check hash-chain linkage over the exact transmitted JSONL octets. The `-01` verifier additionally validates uniqueness, per-chain signed sequence rules, and domain-separated signed-head assertions. Neither imports or executes the upstream verifier.

Current verification evidence:

- **49 repository tests passing**;
- **7 focused `-01` interoperability tests passing**;
- original `-00` and new `-01` pinned workflows passing;
- deterministic report regeneration passing;
- CI, CodeQL, and secret scan passing.

The Governex vector repository publicly links the independent T-Trace/OpenPoC result. The draft author confirmed that the forthcoming `-01` RFC 7942 Implementation Status section will credit **Aleksei Safonov — Independent Researcher and Maintainer of T-Trace/OpenPoC**. Technical feedback from this work informed the new repeated-`step_id`, signed-`seq`, and signed-head vectors.

This is interoperability evidence only. It does not prove the draft correct, prove capture completeness, prevent signer equivocation, or bind a fresh record identity to a unique real-world effect.

## Work plan and milestones

### Weeks 1–2 — benchmark expansion

- add bypass, replay, substitution, effect-digest mismatch, split-view, truncation, stale-head, and configuration-drift vectors;
- define deterministic expected verdicts for each assurance dimension;
- preserve both existing Governex compatibility profiles in CI.

### Weeks 3–4 — evidence-format adapter

- select one current signed-receipt or transparency-log format;
- implement a versioned adapter into a T-Trace causal projection;
- document information preserved, lost, or left unproven.

### Weeks 5–6 — trust model and reproducibility

- specify the evidence needed to justify a non-bypassable gate;
- test stale and replayed pre-commitments, direct-access bypass, fresh-identity semantic replay, and configuration changes;
- define freshness and anti-equivocation requirements for external head state;
- implement OpenPoC-02 for third-party replay recipes, inputs, versions, and environment evidence.

### Weeks 7–8 — external review and release

- invite focused technical review of concrete artifacts;
- resolve or publish disagreements;
- finalize the integration guide, report, CI, and release package.

## Deliverables

1. At least 12 additional adversarial assurance vectors with deterministic expected outcomes.
2. Continued reproducibility of the current 13/13 `-00` and 18/18 `-01` external interoperability results at their pinned commits.
3. One versioned external evidence-format adapter.
4. An executable L1–L4 assurance model.
5. OpenPoC-02 with positive and negative independent-reproducibility fixtures.
6. A public compatibility report, integration guide, and reviewer-facing final report.
7. Green tests, both interoperability workflows, CodeQL, and secret scanning.

## Success criteria

- bypass cases remain structurally valid but cannot receive a complete-assurance verdict;
- mandatory-gate cases block effects lacking required evidence;
- replay, substitution, fresh-identity semantic replay, and stale-head cases produce separate expected verdicts;
- the adapter preserves explicit distinctions between signature validity, record integrity, capture completeness, effect binding, and reproducibility;
- both pinned Governex compatibility profiles remain reproducible;
- at least two external implementers review a concrete artifact or result;
- all claims state their trust assumptions and non-claims;
- all public tests and security checks pass.

A reproducible negative result counts as success when it precisely shows that a proposed mechanism cannot establish capture completeness or independent reproducibility.

## Budget

| Category | Amount |
|---|---:|
| Research and implementation | USD 12,000 |
| External implementation / reviewer support | USD 3,000 |
| Test infrastructure, compute, and integration environments | USD 3,000 |
| Documentation, release work, and contingency | USD 2,000 |
| **Total** | **USD 20,000** |

## Why this applicant

Aleksei Safonov is an independent QA engineer and open-source maintainer focused on adversarial verification, deterministic regression tests, integration boundaries, and evidence-backed safety claims. The project is already being developed through narrow issues, feature branches, executable fixtures, CI, security scanning, and explicit non-claims rather than architecture-only proposals.

The relevant execution pattern has already been demonstrated:

1. identify a falsifiable assurance claim;
2. obtain external technical criticism;
3. encode the boundary as an executable negative fixture;
4. separate structural validity from broader assurance;
5. validate interoperability against an external public suite;
6. identify a missing ordering/repetition distinction;
7. independently verify the resulting `-01` vectors and publish the residual boundary;
8. publish exact results and limitations.

## Counterfactual without funding

Without funding, T-Trace/OpenPoC will remain open source and may continue incrementally, but progress will compete with paid QA work and other obligations. The likely result is slower benchmark expansion, no dedicated external-review budget, and reduced ability to build and validate a full adapter and reproducibility layer within a coherent eight-week sprint.

Funding buys concentrated execution, not a speculative idea: the first benchmark, two external conformance profiles, CI, security checks, and documentation already exist.

## Main risks and mitigations

### Risk: the project duplicates signed-receipt or transparency-log work

**Mitigation:** treat those formats as inputs and adapters, not competitors. T-Trace/OpenPoC focuses on causal projection and assurance boundaries.

### Risk: test fixtures overstate production guarantees

**Mitigation:** keep gate attestation as an explicit fixture assumption; do not claim production TEE, PKI, or deployment assurance.

### Risk: benchmark agreement is mistaken for correctness

**Mitigation:** report conformance as interoperability evidence only, with explicit non-claims about draft correctness, capture completeness, signer non-equivocation, and effect-level anti-replay.

### Risk: weak link to catastrophic risk reduction

**Mitigation:** evaluate the project on a narrow pathway: whether it reduces false assurance in monitoring, control, evaluation, and incident-reconstruction layers used for increasingly autonomous agents.

### Risk: no external adoption

**Mitigation:** prioritize one real evidence-format adapter, public vectors, standards-level interoperability, and direct review from current implementers rather than building a large standalone platform.

## Public summary

T-Trace/OpenPoC is an open-source benchmark and verification project for AI-agent evidence. It tests when a valid trace is insufficient to claim that every safety-relevant action was captured or that a result can be independently reproduced. Existing work demonstrates a selective-omission bypass and independently matches two pinned signed-action-receipt suites: 13/13 checks for the original `-00` profile and 18/18 checks for the forthcoming `-01` vector profile. The proposed sprint expands the benchmark, adds an external evidence adapter, specifies the trust model for capture completeness, and builds independent-reproducibility fixtures.

## Personal fields to complete manually before submission

- country of residence and current location;
- preferred grant recipient: individual or legal entity;
- current employment and time allocation during the eight-week sprint;
- whether any funding is already committed to this exact sprint;
- earliest start date;
- public versus private grant-report preference;
- payment and tax details requested during due diligence;
- any formal references, only after obtaining their consent.
