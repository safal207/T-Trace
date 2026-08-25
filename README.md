# T-Trace

[![CI](https://github.com/safal207/T-Trace/actions/workflows/ci.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/ci.yml)
[![Receipt interop](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/governex-action-receipts.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1-blue.svg)](spec/t-trace.md)

T-Trace is an append-only, JSONL protocol for recording acknowledged state transitions over time.

It is designed for systems that need deterministic replay, auditability, and continuity of meaning across long-running threads.

See `examples/minimal.ttrace.jsonl` for the smallest complete T-Trace sequence.

## Review links

- Grant evidence: [docs/GRANT_EVIDENCE.md](docs/GRANT_EVIDENCE.md)
- Protocol spec: [spec/t-trace.md](spec/t-trace.md)
- Causal Execution Graph profile: [spec/causal-execution-graph-v0.1.md](spec/causal-execution-graph-v0.1.md)
- Portable Causality profile: [spec/portable-causality-profile-v0.1.md](spec/portable-causality-profile-v0.1.md)
- JSON Schema: [schemas/t-trace-record.schema.json](schemas/t-trace-record.schema.json)
- Reference validator: [scripts/validate_ttrace.py](scripts/validate_ttrace.py)
- Portable causality verifier: [scripts/verify_portable_causality.py](scripts/verify_portable_causality.py)
- Canonical trace example: [examples/minimal.ttrace.jsonl](examples/minimal.ttrace.jsonl)
- Canonical fork/reconciliation example: [examples/causal-portability/fork-reconciliation.json](examples/causal-portability/fork-reconciliation.json)
- Assurance levels: [docs/assurance-levels.md](docs/assurance-levels.md)
- OpenPoC-01 selective omission: [docs/openpoc-01-selective-omission.md](docs/openpoc-01-selective-omission.md)
- Liminal research provenance: [docs/liminal-research-provenance.md](docs/liminal-research-provenance.md)
- Governex action-receipt compatibility: [docs/governex-action-receipts-compatibility.md](docs/governex-action-receipts-compatibility.md)

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

### Signed action-receipt interoperability

The separate action-receipt verifier checks Ed25519 signatures and raw-octet hash-chain linkage against a pinned external conformance suite. CI reads the upstream vector data and manifest but does **not** execute the upstream verifier.

The compatibility report records the expected and observed outcomes for all public vectors, including the intentionally undetectable head-truncation limit and unsigned-extension tampering case.

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
- `ttrace/portable_causality.py` - provider-agnostic reference implementation
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
