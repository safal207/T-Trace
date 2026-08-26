# Governex action-receipt -01 compatibility report

- Upstream: `governex/agent-action-receipts-vectors`
- Pinned commit: `6e31f1fabe0f5f6de511c5821bdf8b924d8aaa2a`
- Draft profile: `draft-sahu-agent-action-receipts-01 (vectors 01-18 are unchanged from the -00 suite; 19-21 and the head assertion exercise -01 additions)`
- Verifier: `openpoc/action_receipt_compat_v01.py`
- Upstream verifier execution: **disabled**; CI reads only the pinned manifest and vector data.
- Prior `01–18` / `-00` report: remains pinned and unchanged.

## Result

**18/18 checks agree; 0 disagree; 0 unsupported.**

### Receipt-log vectors

| Vector | Exp. sig fail | Obs. sig fail | Exp. chain | Obs. chain | Exp. step repeat | Obs. step repeat | Exp. seq gap | Obs. seq gap | Exp. seq repeat | Obs. seq repeat | Result |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `01-basic-chain.jsonl` | — | — | — | — | — | — | — | — | — | — | **AGREE** |
| `02-optional-actor.jsonl` | — | — | — | — | — | — | — | — | — | — | **AGREE** |
| `03-extension-members.jsonl` | — | — | — | — | — | — | — | — | — | — | **AGREE** |
| `04-params-shapes.jsonl` | — | — | — | — | — | — | — | — | — | — | **AGREE** |
| `10-tampered-value.jsonl` | 1 | 1 | 2 | 2 | — | — | — | — | — | — | **AGREE** |
| `11-reordered.jsonl` | — | — | 2 | 2 | — | — | — | — | — | — | **AGREE** |
| `12-interior-deleted.jsonl` | — | — | 2 | 2 | — | — | — | — | — | — | **AGREE** |
| `13-duplicated-line.jsonl` | — | — | 3 | 3 | 3 | 3 | — | — | — | — | **AGREE** |
| `14-head-truncated.jsonl` | — | — | — | — | — | — | — | — | — | — | **AGREE** |
| `15-genesis-with-prevhash.jsonl` | — | — | 1 | 1 | — | — | — | — | — | — | **AGREE** |
| `16-missing-prevhash.jsonl` | — | — | 2 | 2 | — | — | — | — | — | — | **AGREE** |
| `17-bad-key-encoding.jsonl` | 1 | 1 | — | — | — | — | — | — | — | — | **AGREE** |
| `18-tampered-extension.jsonl` | — | — | 2 | 2 | — | — | — | — | — | — | **AGREE** |
| `19-replayed-step-id.jsonl` | — | — | — | — | 4 | 4 | — | — | — | — | **AGREE** |
| `20-seq-gap.jsonl` | — | — | — | — | — | — | 3 | 3 | — | — | **AGREE** |
| `21-seq-repeat.jsonl` | — | — | — | — | — | — | — | — | 3 | 3 | **AGREE** |

### Signed head-assertion checks

| Assertion | Log | Expected | Observed | Result |
|---|---|---|---|---|
| `30-head-assertion.json` | `01-basic-chain.jsonl` | `match` | `match` | **AGREE** |
| `30-head-assertion.json` | `14-head-truncated.jsonl` | `mismatch` | `mismatch` | **AGREE** |

## Capture-side reading

- `19-replayed-step-id` isolates semantic record repetition: signatures and raw-octet linkage remain valid, while repeated `step_id` is rejected.
- `20-seq-gap` and `21-seq-repeat` distinguish a missing signed position from a reused/regressed signed position inside the optional per-chain sequence profile.
- `30-head-assertion.json` detects presentation of the truncated vector relative to a particular signed external head state.

These mechanisms separate record repetition, recorder-issued positional anomalies, and head truncation. They do **not** by themselves prove that every real effect was captured. In particular:

- a repeated real-world effect with a fresh `step_id` and the next valid `seq` remains record-valid unless a stable effect identity, authorization nonce, request digest, or idempotency binding is also signed;
- a `seq` gap proves a gap in the recorder's signed numbering, not an unrecorded effect, unless sequence allocation is itself non-bypassable and occurs before the effect;
- a head assertion proves consistency against that assertion; preventing equivocation between multiple valid assertions still requires witness, gossip, transparency, or another monotonic external state.

## Non-claims

Agreement is interoperability evidence only. It does not:

- prove the draft correct or complete;
- prove real-world capture completeness;
- prove that the head signer cannot equivocate;
- turn `step_id` or `seq` into effect-level anti-replay binding;
- constitute endorsement in either direction.
