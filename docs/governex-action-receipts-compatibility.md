# Governex action-receipt compatibility report

- Upstream: `governex/agent-action-receipts-vectors`
- Pinned commit: `65836f4e1ecb96ff22e8b4ab6a7c086532ce564c`
- Draft profile: `draft-sahu-agent-action-receipts-00`
- Verifier: `openpoc/action_receipt_compat.py`
- Upstream verifier execution: **disabled**; CI reads only the manifest and vector data.

## Result

**13/13 vectors agree; 0 disagree; 0 unsupported.**

| Vector | Expected signature failures | Observed signature failures | Expected chain break | Observed chain break | Result |
|---|---:|---:|---:|---:|---|
| `01-basic-chain.jsonl` | — | — | — | — | **AGREE** |
| `02-optional-actor.jsonl` | — | — | — | — | **AGREE** |
| `03-extension-members.jsonl` | — | — | — | — | **AGREE** |
| `04-params-shapes.jsonl` | — | — | — | — | **AGREE** |
| `10-tampered-value.jsonl` | 1 | 1 | 2 | 2 | **AGREE** |
| `11-reordered.jsonl` | — | — | 2 | 2 | **AGREE** |
| `12-interior-deleted.jsonl` | — | — | 2 | 2 | **AGREE** |
| `13-duplicated-line.jsonl` | — | — | 3 | 3 | **AGREE** |
| `14-head-truncated.jsonl` | — | — | — | — | **AGREE** |
| `15-genesis-with-prevhash.jsonl` | — | — | 1 | 1 | **AGREE** |
| `16-missing-prevhash.jsonl` | — | — | 2 | 2 | **AGREE** |
| `17-bad-key-encoding.jsonl` | 1 | 1 | — | — | **AGREE** |
| `18-tampered-extension.jsonl` | — | — | 2 | 2 | **AGREE** |

## Boundary cases

- `14-head-truncated.jsonl` verifies clean. This is expected: a self-anchored chain has no internal evidence that an omitted final record ever existed.
- `18-tampered-extension.jsonl` keeps every signature valid while the chain breaks at line 2. The link covers the previous record's exact transmitted octets, including extension members outside the signed subset.

## Method

The T-Trace/OpenPoC verifier separately computes:

1. the fixed-order signed receipt byte sequence;
2. recursive canonicalization of `params` with integer-only numbers;
3. Ed25519 signature validity and strict lowercase key/signature encoding;
4. the first hash-chain break using SHA-256 of the previous raw JSONL line.

The upstream repository is checked out at the pinned commit in CI. Its `verify.py` is not imported or executed.

## Non-claims

Agreement with the manifest is interoperability evidence only. It does not:

- prove that the draft is correct or complete;
- prove that every real-world action entered the receipt path;
- turn a self-anchored chain into proof against head truncation;
- constitute endorsement by the upstream authors.
