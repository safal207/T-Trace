# Third-Party Agent Evaluation: What Can a Trace Prove?

**Compact reviewer brief · 18 October 2026**  
**Project:** [T-Trace / OpenPoC](https://github.com/safal207/T-Trace)  
**Status:** Open-source evidence and synthetic conformance examples, **not independent certification, endorsement by a frontier AI lab, or proof of global completeness**.

## Question

> For a long-horizon AI agent evaluation, what minimum evidence could support the claim that a recorded trajectory is complete rather than selectively omitted, rewritten or merely plausible?

**Short answer:** A structurally valid trace does **not** prove completeness. A stronger evaluation requires a separately accepted source of expected effects, or a trusted counterpart/receipt/witness boundary, with explicit scope, timestamps, integrity and missing-evidence verdicts. Even matching two supplied snapshots cannot prove neither source omitted an event.

## Three runnable negative controls

Start on a fresh checkout, record its commit and install Python 3.9+ dependencies in an isolated environment:

```bash
git clone https://github.com/safal207/T-Trace.git
cd T-Trace
git rev-parse HEAD
python -m pip install -e ".[dev]"
```

The following are **existing fixtures**. They contain no real payments, personal data or external agent actions.

### Control A — a valid trace with an omitted real-world effect

```bash
python scripts/validate_ttrace.py examples/minimal.ttrace.jsonl
python -m openpoc.verify_assurance examples/openpoc-01/bypass.scenario.json
```

- The simple trace should pass structural validation.
- The separate bypass/effect inventory fixture should produce `trace_valid=true`, `capture_status=violated`, `effect_bound=false`, `overall_assurance=insufficient`.
- **What it proves:** A valid presented trace and an insufficient capture claim can coexist. It is the **separate declared effect inventory**, not magic reasoning over a single log, that exposes the omitted event.

[Full bounded documentation](openpoc-01-selective-omission.md).

### Control B — reproducible computation from an incomplete input

```bash
python -m openpoc.verify_reproducibility examples/openpoc-02/complete-replay.scenario.json
python -m openpoc.verify_reproducibility examples/openpoc-02/incomplete-but-reproducible.scenario.json
```

- The second example's declared computation reproduces but its completeness claim fails.
- Expected: `relation_satisfied=true`, `capture_status=violated`, `claim_verdict=violated`.
- **What it proves:** Deterministic replay over exactly supplied inputs and actual completeness are distinct properties.

[Full bounded documentation](openpoc-02-independent-reproducibility.md).

### Control C — a missing counterpart in two source snapshots

```bash
python -m openpoc.verify_cross_source \
  examples/openpoc-03/counterpart-omission.scenario.json
```

- Expected: `pairwise_consistency_status=violated`, missing receiver counterpart for `comm-2`, `global_completeness_status=unproven`.
- **What it proves:** One bounded pairwise mismatch under declared snapshot-finality assumptions. It does **not** prove global capture completeness, responsibility, or authenticity of the supplied finality claim.

[Full bounded documentation](openpoc-03-cross-source-correlation.md).

## Evidence ladder

| Evidence supplied | Appropriate claim | Claim **not** supported |
| --- | --- | --- |
| One internally valid log | Structurally valid *presented* trajectory | Full execution capture |
| Reproducible run from a fixed log | The declared computation replays from the supplied inputs | Inputs were exhaustive, trusted or unbiased |
| External effect inventory/counterpart | A specified missing or conflicting effect relative to **that** accepted source | No omitted effects exist outside both sources |
| Hashes/signatures | Selected bytes are bound and may have verified provenance under an accepted trust root | Witness watched everything or reported external outcome is true |
| Independently accepted source policy + pinned epoch/cutoff | Claim-scoped assurance within that source, window and finality model | Safety or completeness of all agent activity |

The [Asqav three-vector compatibility report](asqav-frozen-package-report.md) and [Governex -00/-01 reports](reviewer-path.md) provide selected interoperability results. These are **separate** from this completeness claim and are not an independent lab endorsement.

## Possible external-evaluation follow-up

The most defensible next artefact is a **one-page confusion and failure matrix** for short, synthetic trajectories:

- intact trace + matching external effect inventory;
- syntactically valid trace + omitted effect;
- changed/replayed trace + invalid byte/integrity binding;
- missing counterpart with declared snapshot finality;
- both sources missing the same effect (must remain `unproven`, not `complete`);
- late-arriving evidence after cutoff (must not retroactively repair a prior verdict).

**Proposed metrics, not yet measured in this brief:** omission-detection true/false positives, accepted uncertainty rate, replay stability, minimal trusted source assumptions, and reviewer time. Freeze dataset/fixtures and reference baselines before publishing numbers.

## Responsible outreach

This is a **technical context package**, not a proof that Anthropic or any research team accepted or reviewed T-Trace. Earlier outreach about minimum completeness evidence was already sent in August 2026; any future contact should link **this substantively new artifact**, check the original thread first, and ask only one methodology question. No duplicate bulk outreach; no private data or unconfirmed security findings.

**Reviewer landing page:** [docs/reviewer-path.md](reviewer-path.md) · [project README](../README.md).
