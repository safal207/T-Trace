# Asqav verification-path consolidation

Comparison date: 2026-09-06. This is a documentation decision and scoped
follow-up plan, not a merge, closure, or security approval of the open PR.

## Exact compared revisions

- Merged path: [PR #38](https://github.com/safal207/T-Trace/pull/38), main commit
  `3126937608ab5c8164ace103f3cfb08e2ad852b6`.
- Open alternative: [PR #37](https://github.com/safal207/T-Trace/pull/37), head
  `ee7b8830f0de4beed84befe1d8b76ff0fa221237`.
- Shared upstream subject: `jagmarques/asqav-sdk` commit
  `17c814f9e2e51f005faa707d44adec0316534da8`, vectors 14, 15, and 16 only.

The overlap was inspected in source, tests, workflows, and reports. The open
branch was not merged or executed as part of that comparison; its tests are
described as present, not freshly passing.

## Shared work and useful differences

| Area | Merged #38 | Open #37 |
|---|---|---|
| Receipt verification | Independent Ed25519 signatures, predecessor links, and markers | A second implementation of the same selected receipt subject |
| Input distribution | Reads data from the pinned upstream checkout in CI | Includes 10 frozen local files, mappings to 12 upstream paths, and file pins |
| Source binding | Workflow pins the upstream checkout; CLI source revision is metadata | Separate comparison of checkout revision, raw paths, selected manifest records, and lock records |
| Reports | JSON and Markdown regenerated in CI | JSON report plus a written cross-verification explanation |
| Regression emphasis | Synthetic signed controls for receipt/chain/marker behavior | Frozen-vector tests plus controls for local bytes and upstream source drift |
| Execution setup | Action SHAs, Python/dependency versions, timeout, and checkout credentials explicitly configured | Different workflow with action version tags and a broader dependency install |
| Wording | Signed observability markers and bounded non-claims | More explicit distinction between locally checked facts and upstream-declared scenario causes |

No row is an overall assurance score. Neither path establishes capture
completeness, full Asqav conformance, or production gate non-bypassability.

## Decision for the reviewer entry point

Keep the merged [capture comparison](asqav-capture-compatibility.md),
[`openpoc/asqav_capture_compat.py`](../openpoc/asqav_capture_compat.py), and its
[workflow](../.github/workflows/asqav-capture-compatibility.yml) as the single
documented default. Do not direct new readers to an unmerged alternative.

Do not discard #37 as a pure duplicate: frozen-input distribution and explicit
source binding address reproducibility outside the original CI environment.
Keep those as a bounded follow-up to the default path, subject to focused
review. This does not claim the alternative's source-binding implementation
is already suitable for arbitrary untrusted input packages.

## Follow-up acceptance checklist

- [ ] Compare and preserve only useful unique frozen inputs, source mappings,
  and relevant controls; avoid merging two competing default receipt CLIs.
- [ ] Authenticate the selected source revision and raw input bytes separately
  from receipt signature verification and from report metadata.
- [ ] Define the trust origin for the source manifest; a package must not make
  itself trusted merely by carrying matching hashes and public keys.
- [ ] Document acquisition-time source verification separately from offline
  verification of an already authenticated frozen package.
- [ ] Preserve the existing three-vector result and distinguish verified
  declarations from asserted external causes.
- [ ] Regenerate reports from exact inputs and run both the default regression
  suite and any retained source-binding controls on the final commit.
- [ ] Preserve the current pinned execution setup when consolidating CI.
- [ ] Link the completed work from #37 before deciding its disposition. Until
  then, leave the PR open; this document does not close or approve it.

No new witness, gossip, or transparency protocol is needed for this step.
