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
- JSON Schema: [schemas/t-trace-record.schema.json](schemas/t-trace-record.schema.json)
- Reference validator: [scripts/validate_ttrace.py](scripts/validate_ttrace.py)
- Canonical example: [examples/minimal.ttrace.jsonl](examples/minimal.ttrace.jsonl)
- Assurance levels: [docs/assurance-levels.md](docs/assurance-levels.md)
- OpenPoC-01 selective omission: [docs/openpoc-01-selective-omission.md](docs/openpoc-01-selective-omission.md)
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

The current compatibility report records the exact expected and observed outcomes for all 13 public vectors, including the intentionally undetectable head-truncation limit and the unsigned-extension tampering case.

## Why T-Trace

Event logs often capture *what happened* but not whether transitions were causally coherent and acknowledged.

T-Trace adds a strict record shape and invariants so traces are machine-verifiable and reproducible:

- strict record envelope (`id`, `type`, `ts`, `thread_id`)
- canonical record types (`sense`, `transition`, `commit`)
- per-thread timestamp monotonicity
- uniqueness of record identifiers
- transition/commit causality checks

## Quick Start

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
```

Expected output:

```text
PASS examples/minimal.ttrace.jsonl (3 records)
```

## Repository Layout

- `spec/t-trace.md` - normative protocol specification
- `schemas/t-trace-record.schema.json` - JSON Schema for record envelope
- `scripts/validate_ttrace.py` - reference validator
- `openpoc/` - executable assurance-boundary and interoperability fixtures
- `examples/` - canonical trace and OpenPoC examples
- `tests/` - validator, OpenPoC, and interoperability regression tests

## Validation Matrix

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
