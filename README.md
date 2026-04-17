# T-Trace
T-Trace is a line-based format for recording state transitions over time, designed to preserve continuity of meaning in long-running systems.

See `examples/minimal.ttrace.jsonl` for the smallest complete T-Trace sequence.

## Boundaries
T-Trace intentionally excludes logs, metrics, raw events, and observability data. Only acknowledged state transitions belong in a trace.

See `examples/forbidden.ttrace.jsonl` for examples of what T-Trace is NOT.
