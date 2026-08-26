# Capture-side review of Governex action-receipt `-01` vectors

## Verdict

The new vectors cleanly separate three record-level questions:

1. **repetition of record identity** — `19-replayed-step-id`;
2. **signed positional gap versus repeated/regressed position** — `20-seq-gap` and `21-seq-repeat`;
3. **presentation truncation relative to an external signed state** — `30-head-assertion.json` against the complete and truncated logs.

T-Trace/OpenPoC's separate verifier agrees with all of those expected outcomes at the pinned upstream commit.

## Why the separation is useful

### Repeated `step_id`

An intact chain can contain a newly signed, newly linked record that reuses an earlier `step_id`. Signature validity and linkage are therefore insufficient; uniqueness is a separate invariant.

### `seq` gap versus repeat

The signed optional `seq` profile distinguishes:

- `0,1,3`: a position is absent from the signer's numbering;
- `0,1,1`: a position was assigned more than once or the sequence regressed.

This is more informative than linkage alone because both files can be internally hash-chain-consistent.

### Signed head assertion

The same valid assertion matches the complete log and mismatches the head-truncated presentation. This is the correct external-state answer to a truncation that the self-contained chain cannot reveal.

## Remaining capture-side boundary

The vectors do not conflate the three cases above, but they intentionally do not cover every form of replay or omission.

### Fresh-record semantic effect replay

A real-world effect may be executed twice while the second receipt uses:

- a fresh `step_id`;
- the next valid `seq`;
- a valid signature;
- a valid raw-octet chain link.

All record-level `-01` checks then pass. Detecting or preventing that case requires a signed stable effect identity, authorization nonce, request digest, idempotency key, or equivalent application-level binding at the effect boundary.

### What a `seq` gap proves

A `seq` gap proves a gap in the recorder's signed numbering. It is not by itself proof that a real-world effect occurred without a receipt. That stronger inference requires sequence allocation to be non-bypassable and to occur before the effect.

### What a head assertion proves

A head assertion proves consistency against that particular signed external state. Preventing the signer from issuing conflicting valid assertions still requires witness, gossip, transparency, monotonic storage, or another anti-equivocation mechanism.

## Recommendation before freezing `-01`

The three vectors are well-separated and suitable as written. The remaining semantic-effect replay case is orthogonal rather than a flaw in them. It should be documented as a security boundary and may become a future application-profile vector once the receipt format has a stable effect-identity or authorization-binding field.

## Non-claim

This review is an independent interoperability and threat-boundary assessment. It is not proof that the draft is correct, proof of capture completeness, or endorsement in either direction.
