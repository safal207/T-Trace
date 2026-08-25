# T-Trace

[![CI](https://github.com/safal207/T-Trace/actions/workflows/ci.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/ci.yml)
[![Portable Causality](https://github.com/safal207/T-Trace/actions/workflows/portable-causality.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/portable-causality.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1-blue.svg)](spec/t-trace.md)

T-Trace is an append-only protocol for recording acknowledged state transitions and preserving their causal meaning over time.

The repository contains two compatible layers:

1. the original strict JSONL trace format;
2. draft portable-causality profiles for distributed execution, semantic state identity, multi-epoch transitions, forks, and reconciliation.

## Portable causal core

The clean `ttrace` reference package introduces:

```text
CausalStateRef
      ↓
CausalTransitionRef
      ↓
ForkBranchRef
      ↓
CausalReconciliationRef
```

The key design rule is:

> **Evidence proves portable causal identity; provider-specific evidence does not automatically become that identity.**

This allows different verified histories, signers, providers, or representations to establish the same semantic state while retaining their raw provenance separately.

The fork/reconciliation profile preserves both divergent lineages through a canonical two-parent DAG join. It does not silently select one branch and erase the other.

Run the native reference proof:

```bash
pip install -e .[dev]
python -m pytest -q tests/test_portable_causality.py
python scripts/verify_portable_causality.py \
  examples/portable-causal/two-parent-reconciliation.json
```

## Specifications

- Base protocol: [`spec/t-trace.md`](spec/t-trace.md)
- Causal execution graph: [`spec/causal-execution-graph-v0.1.md`](spec/causal-execution-graph-v0.1.md)
- Portable causal state: [`spec/portable-causal-state-v0.1.md`](spec/portable-causal-state-v0.1.md)
- Portable causal transition: [`spec/portable-causal-transition-v0.1.md`](spec/portable-causal-transition-v0.1.md)
- Fork/reconciliation: [`spec/causal-fork-reconciliation-v0.1.md`](spec/causal-fork-reconciliation-v0.1.md)
- Threat model: [`docs/THREAT_MODEL_PORTABLE_CAUSALITY.md`](docs/THREAT_MODEL_PORTABLE_CAUSALITY.md)
- Research provenance: [`proofs/liminal-research-provenance.md`](proofs/liminal-research-provenance.md)

## Original JSONL protocol

The original T-Trace format remains available and backward-compatible. It is designed for systems that need deterministic replay, auditability, and continuity of meaning across long-running threads.

See `examples/minimal.ttrace.jsonl` for the smallest complete T-Trace sequence.

### Review links

- Grant evidence: [docs/GRANT_EVIDENCE.md](docs/GRANT_EVIDENCE.md)
- Protocol spec: [spec/t-trace.md](spec/t-trace.md)
- JSON Schema: [schemas/t-trace-record.schema.json](schemas/t-trace-record.schema.json)
- Reference validator: [scripts/validate_ttrace.py](scripts/validate_ttrace.py)
- Canonical example: [examples/minimal.ttrace.jsonl](examples/minimal.ttrace.jsonl)
- Assurance levels: [docs/assurance-levels.md](docs/assurance-levels.md)
- OpenPoC-01 selective omission: [docs/openpoc-01-selective-omission.md](docs/openpoc-01-selective-omission.md)

## Boundaries

T-Trace intentionally excludes ordinary logs, metrics, raw events, and observability exhaust. Only acknowledged state transitions and the evidence needed to interpret them belong in the protocol.

A valid T-Trace proves that the **presented records** satisfy the active structural and causal profile. It does not by itself prove:

- every real-world effect was captured;
- a bypass path did not exist;
- an authority was socially legitimate;
- a conflict-resolution policy was safe;
- retained evidence will remain available indefinitely.

[OpenPoC-01](docs/openpoc-01-selective-omission.md) demonstrates the selective-capture boundary: a real effect occurs outside the recorder while the shorter presented trace still validates correctly.

```bash
python -m openpoc.verify_assurance \
  examples/openpoc-01/bypass.scenario.json
```

## Why T-Trace

Event logs often capture *what happened* but not whether transitions were acknowledged, causally coherent, correctly authorized, or bound to the execution that produced them.

T-Trace adds explicit invariants so records are machine-verifiable and reproducible:

- strict record and profile shapes;
- acknowledged transition semantics;
- explicit causal parents rather than timestamp authority;
- separation of logical operation and execution attempt;
- portable semantic state and transition identity;
- full-prefix validation;
- explicit fork lineage and canonical reconciliation;
- independent provenance retained outside portable identity.

## Quick start — JSONL validator

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
```

Expected output:

```text
PASS examples/minimal.ttrace.jsonl (3 records)
```

## Repository layout

- `spec/` — base and profile specifications
- `schemas/` — JSON schemas for the original record envelope
- `scripts/validate_ttrace.py` — original JSONL validator
- `ttrace/` — portable-causality reference implementation
- `openpoc/` — executable assurance-boundary fixtures
- `examples/` — canonical JSONL and portable-causality examples
- `tests/` — validator, OpenPoC, and portable-causality regression tests
- `proofs/` — proof provenance and explicit claim boundaries

## Development

```bash
pip install -e .[dev]
python -m pytest -q
```

## Security and governance

- Security policy: [`SECURITY.md`](SECURITY.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## License

MIT. See [`LICENSE`](LICENSE).
