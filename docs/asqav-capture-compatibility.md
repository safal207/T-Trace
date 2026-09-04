# Asqav omission and recovery compatibility report

- Upstream: `jagmarques/asqav-sdk`
- Pinned commit: `17c814f9e2e51f005faa707d44adec0316534da8`
- Vectors: `asqav-14`, `asqav-15`, `asqav-16`
- Verifier: `openpoc/asqav_capture_compat.py`
- Upstream verifier execution: **disabled**; only pinned vector data is read.

## Result

**3/3 vectors agree; 0 disagree; 0 unsupported.**

| Vector | Independent crypto/link check | Marker | What becomes observable | Claim ceiling | Result |
|---|---|---|---|---|---|
| `asqav-14-omitted-action-chain` | signatures + link valid | `none` | silent without external ground truth | integrity of presented receipts only | **AGREE** |
| `asqav-15-unsigned-gap` | signatures + link valid | `unsigned_gap(count=2)` | signer outage window declared | does not prove unsigned actions were policy evaluated | **AGREE** |
| `asqav-16-chain-emission-blocked` | signatures + link valid | `chain_emission_blocked` | blocked emission interval detectable after resume | recorded fail closed recovery event not deployment non bypassability | **AGREE** |

## T-Trace / OpenPoC reading

### 14 — omitted action, intact chain

Both receipts and their link verify. The missing action leaves no in-band evidence because it never reached the signer. Under the vector's external fixture truth, capture is violated while record integrity still passes. This matches OpenPoC-01: `trace_valid=true` does not raise the capture claim above `overall_assurance=insufficient`.

### 15 — signed `unsigned_gap`

The next valid receipt carries a signed outage window. This makes a signer failure observable, but it does not identify the omitted actions or prove that they were policy-evaluated. The honest state is partial observability with effect binding left indeterminate.

### 16 — `chain_emission_blocked` lifecycle receipt

Emission failure causes a recorded deny, and the lifecycle receipt links into the chain after recovery. This is stronger than a silent gap because the blocked interval becomes inspectable. It is still not proof that every production effect path was non-bypassable; that remains a deployment assumption or a separately attested property.

## Independent method

For each pinned vector, this repository independently:

1. resolves the exact active Ed25519 key by `kid` and signed issuer;
2. canonicalizes only the signed payload with the repository's restricted deterministic JSON implementation;
3. verifies predecessor and receipt signatures;
4. re-derives `previousReceiptHash` from SHA-256 of the predecessor's canonical payload;
5. checks the semantic marker without executing upstream code.

## Non-claims

This report is bounded interoperability and claim-ceiling evidence. It does not prove global capture completeness, deployment non-bypassability, policy evaluation of unsigned actions, absence of effects outside the receipt path, or endorsement in either direction.
