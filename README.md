<!-- seo-product-intro:start -->
# T-Trace — AI Agent Verification, Action Receipts & Deterministic Replay

[![CI](https://github.com/safal207/T-Trace/actions/workflows/ci.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/ci.yml)
[![Receipt interop -00](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts.yml)
[![Receipt interop -01](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts-v01.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts-v01.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1-blue.svg)](spec/t-trace.md)

**An open JSONL protocol and executable benchmark for AI-agent action receipts, causal state transitions, deterministic replay, and assurance-boundary verification.**

T-Trace helps teams distinguish four claims that are often collapsed into one:

```text
presented trace is structurally valid
               ≠
evidence is fresh and action-bound
               ≠
every real-world effect was captured
               ≠
the claimed outcome was independently reproduced
```

Use T-Trace/OpenPoC to test stale or replayed evidence, selective omission, recorder bypass, causal ordering, signed receipt interoperability, and unsupported success claims.

## Why T-Trace exists

Event logs answer **what was recorded**. T-Trace adds machine-checkable transition semantics and an explicit assurance layer for asking **what the records actually prove**.

| Need | T-Trace/OpenPoC provides |
|---|---|
| AI-agent verification | Executable negative fixtures for stale, replayed, incomplete, or bypassed evidence |
| Action receipts | Signed-receipt verification and raw-octet hash-chain interoperability |
| Deterministic replay | Strict record envelopes, causal transition/commit rules, and portable profiles |
| Audit-trail boundaries | Claim-scoped verdicts for trace validity, capture completeness, effect binding, and reproducibility |
| Independent evidence | Separate from-scratch verifiers matching **13/13 Governex `-00` vectors** and **18/18 Governex `-01` checks** without importing or executing the upstream verifier |

**External interoperability:** Governex publicly links the independent T-Trace/OpenPoC evidence, and the draft author has confirmed named RFC 7942 Implementation Status credit for the forthcoming `-01` revision. This is independent interoperability and threat-boundary work — not co-authorship, IETF adoption, or endorsement.

**Start here:** [OpenPoC-01 selective omission](docs/openpoc-01-selective-omission.md) · [OpenPoC-02 independent reproducibility](docs/openpoc-02-independent-reproducibility.md) · [Governex `-01` compatibility report](docs/governex-action-receipts-v01-compatibility.md) · [Protocol specification](spec/t-trace.md)
<!-- seo-product-intro:end -->

## Review links

- Grant evidence: [docs/GRANT_EVIDENCE.md](docs/GRANT_EVIDENCE.md)
- Protocol spec: [spec/t-trace.md](spec/t-trace.md)
- Causal Execution Graph profile: [spec/causal-execution-graph-v0.1.md](spec/causal-execution-graph-v0.1.md)
- Portable Causality profile: [spec/portable-causality-profile-v0.1.md](spec/portable-causality-profile-v0.1.md)
- Witness-policy handoff-chain membership profile: [spec/witness-policy-handoff-chain-membership-profile-v0.1.md](spec/witness-policy-handoff-chain-membership-profile-v0.1.md)
- JSON Schema: [schemas/t-trace-record.schema.json](schemas/t-trace-record.schema.json)
- Reference validator: [scripts/validate_ttrace.py](scripts/validate_ttrace.py)
- Portable causality verifier: [scripts/verify_portable_causality.py](scripts/verify_portable_causality.py)
- Canonical trace example: [examples/minimal.ttrace.jsonl](examples/minimal.ttrace.jsonl)
- Canonical fork/reconciliation example: [examples/causal-portability/fork-reconciliation.json](examples/causal-portability/fork-reconciliation.json)
- Assurance dimensions: [docs/assurance-levels.md](docs/assurance-levels.md)
- OpenPoC-01 selective omission: [docs/openpoc-01-selective-omission.md](docs/openpoc-01-selective-omission.md)
- OpenPoC-02 independent reproducibility: [docs/openpoc-02-independent-reproducibility.md](docs/openpoc-02-independent-reproducibility.md)
- Liminal research provenance: [docs/liminal-research-provenance.md](docs/liminal-research-provenance.md)
- Governex `-00` action-receipt compatibility: [docs/governex-action-receipts-compatibility.md](docs/governex-action-receipts-compatibility.md)
- Governex `-01` action-receipt compatibility: [docs/governex-action-receipts-v01-compatibility.md](docs/governex-action-receipts-v01-compatibility.md)
- Governex `-01` capture-side review: [docs/governex-action-receipts-v01-capture-review.md](docs/governex-action-receipts-v01-capture-review.md)

## Boundaries

T-Trace intentionally excludes logs, metrics, raw events, and observability data. Only acknowledged state transitions belong in a trace.

See `examples/forbidden.ttrace.jsonl` for examples of what T-Trace is NOT.

### Assurance boundary

A valid T-Trace proves that the **presented records** satisfy the protocol's structural and causal rules. It does not by itself prove that every real-world effect was captured, that an action could not bypass the recorder, or that a claimed outcome was independently reproduced.

[OpenPoC-01](docs/openpoc-01-selective-omission.md) demonstrates the key negative case: a real effect occurs outside the recorder while the shorter presented trace still validates correctly. The assurance verifier therefore reports trace validity separately from capture completeness.

```bash
python -m openpoc.verify_assurance \
  examples/openpoc-01/bypass.scenario.json
```

[OpenPoC-02](docs/openpoc-02-independent-reproducibility.md) binds a replay
recipe, inputs, expected output, and runtime contract. Its key negative fixture
reproduces the exact claimed relation over an integrity-bound but incomplete
input while independently failing the capture-completeness claim.

```bash
python -m openpoc.verify_reproducibility \
  examples/openpoc-02/incomplete-but-reproducible.scenario.json
```

### Signed action-receipt interoperability

T-Trace/OpenPoC preserves two separate pinned interoperability profiles:

- **`-00`: 13/13 vectors agree** at upstream commit `65836f4e1ecb96ff22e8b4ab6a7c086532ce564c`;
- **`-01`: 18/18 checks agree** — 16 receipt-log vectors plus 2 signed-head checks — at upstream commit `6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a`.

Both verifiers independently reconstruct signed bytes, validate Ed25519 signatures, and check raw-octet hash-chain linkage. The `-01` profile additionally checks repeated `step_id`, signed `seq` gaps/reuse, and the domain-separated signed-head assertion. CI reads pinned upstream vector data and manifests but does **not** import or execute the upstream verifier.

The compatibility work also records the remaining assurance boundaries:

- a fresh `step_id` and the next valid `seq` do not by themselves prevent replay of the same real-world effect;
- a signed `seq` gap proves a gap in recorder numbering, not necessarily an unrecorded external effect;
- a signed head proves consistency with that checkpoint, not checkpoint freshness or signer non-equivocation.

Technical feedback from the T-Trace/OpenPoC review informed the new repeated-`step_id`, signed-`seq` gap/reuse, and signed-head assertion vectors. Governex links the independent evidence from its public vector repository, and the draft author has confirmed named T-Trace/OpenPoC credit in the forthcoming RFC 7942 Implementation Status section.

Evidence:

- [`-00` 13/13 report](docs/governex-action-receipts-compatibility.md) · [`-00` verifier](openpoc/action_receipt_compat.py) · [`-00` pinned workflow](.github/workflows/governex-action-receipts.yml)
- [`-01` 18/18 report](docs/governex-action-receipts-v01-compatibility.md) · [`-01` capture review](docs/governex-action-receipts-v01-capture-review.md) · [`-01` verifier](openpoc/action_receipt_compat_v01.py) · [`-01` pinned workflow](.github/workflows/governex-action-receipts-v01.yml)

## Why T-Trace

Event logs often capture *what happened* but not whether transitions were causally coherent and acknowledged.

T-Trace adds strict record invariants and optional causal profiles so traces can be machine-verified without confusing evidence provenance with semantic identity:

- strict record envelope (`id`, `type`, `ts`, `thread_id`)
- canonical record types (`sense`, `transition`, `commit`)
- per-thread timestamp monotonicity for the base v0.1 model
- uniqueness of record identifiers
- transition/commit causality checks
- explicit DAG lineage for distributed execution profiles
- canonical semantic state and transition references
- genuine fork detection and two-parent reconciliation

## Quick Start

Validate the canonical base trace:

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
```

Expected output:

```text
PASS examples/minimal.ttrace.jsonl (3 records)
```

Verify the Portable Causality example:

```bash
python scripts/verify_portable_causality.py \
  examples/causal-portability/fork-reconciliation.json
```

The verifier checks two independently evidenced, semantically divergent branches and a canonical order-independent two-parent reconciliation.

## Portable Causality Profile

The optional profile separates three identities:

```text
provider evidence
      ↓ proves
portable StateRef
      ↓ evolves through
portable TransitionRef / ForkBranchRef
      ↓ reconciles through
canonical two-parent ReconciliationRef
```

Provider, signer, registry, manifest, workflow-run, and storage identities remain evidence. They do not become the portable state's identity merely because they established it.

The base T-Trace v0.1 validator is intentionally unchanged; profile objects are additional payload semantics with a focused verifier.

## Repository Layout

- `spec/t-trace.md` - normative base protocol specification
- `spec/causal-execution-graph-v0.1.md` - distributed causal graph profile
- `spec/portable-causality-profile-v0.1.md` - portable semantic identity and reconciliation profile
- `schemas/t-trace-record.schema.json` - JSON Schema for the base record envelope
- `scripts/validate_ttrace.py` - base reference validator
- `scripts/verify_portable_causality.py` - focused portable-causality verifier
- `scripts/verify_witness_policy_handoff_chain_membership.py` - selective historical witness-policy rotation verifier
- `ttrace/portable_causality.py` - provider-agnostic reference implementation
- `ttrace/lineage_witness_handoff_chain_membership.py` - handoff-chain membership anchor and selective-disclosure implementation
- `openpoc/` - executable assurance-boundary and interoperability fixtures
- `examples/` - canonical traces and profile examples
- `tests/` - validator, OpenPoC, interoperability, and profile regression tests

## Base Validation Matrix

- JSON object on every line
- required fields present
- allowed `type` set only
- unique `id` values
- valid timestamp (`ISO 8601` or unix epoch)
- monotonic `ts` ordering within each `thread_id`
- `transition` requires prior `sense` or `transition` in thread
- `commit` requires prior `transition` in thread

## Development

```bash
pip install -e .[dev]
python -m pytest -q
```

## Security and Governance

- Security policy: [`SECURITY.md`](SECURITY.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## License

MIT. See [`LICENSE`](LICENSE).
