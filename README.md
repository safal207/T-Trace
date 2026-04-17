# T-Trace

[![CI](https://github.com/safal207/T-Trace/actions/workflows/ci.yml/badge.svg)](https://github.com/safal207/T-Trace/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1-blue.svg)](spec/t-trace.md)

T-Trace is an append-only, JSONL protocol for recording acknowledged state transitions over time.

It is designed for systems that need deterministic replay, auditability, and continuity of meaning across long-running threads.

See `examples/minimal.ttrace.jsonl` for the smallest complete T-Trace sequence.

## Boundaries

T-Trace intentionally excludes logs, metrics, raw events, and observability data. Only acknowledged state transitions belong in a trace.

See `examples/forbidden.ttrace.jsonl` for examples of what T-Trace is NOT.

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
- `examples/` - canonical trace examples
- `tests/` - validator regression tests

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