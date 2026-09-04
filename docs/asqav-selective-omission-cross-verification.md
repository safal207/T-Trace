# Asqav selective-omission cross-verification

## Result

`3/3 AGREE` for three frozen Asqav-native vectors at upstream commit
`17c814f9e2e51f005faa707d44adec0316534da8`.

Two independent gates are exercised:

1. **Source binding.** CI checks out the exact upstream commit and compares 12
   upstream raw paths against the 10 locally frozen files. It also verifies the
   three selected `manifest.json` records and 12 corresponding
   `manifest.lock.json` records.
2. **Receipt verification.** A separate verifier that imports no Asqav code
   reconstructs the selected-corpus JCS payload bytes, verifies six Ed25519
   signatures, rederives all three `previousReceiptHash` links, checks the
   selected semantic markers, and regenerates the report deterministically.

The focused regression suite contains 11 tests, including negative controls for
signed-payload mutation, chain mutation, non-integer canonicalization, local raw
file tampering, and upstream source drift.

Machine-readable result:
[`asqav-selective-omission-compatibility.json`](./asqav-selective-omission-compatibility.json)

Receipt verifier:
[`openpoc/asqav_omission_compat.py`](../openpoc/asqav_omission_compat.py)

Exact-source binding verifier:
[`openpoc/asqav_upstream_binding.py`](../openpoc/asqav_upstream_binding.py)

Frozen inputs and pins:
[`examples/asqav-selective-omission/`](../examples/asqav-selective-omission/)

## What agrees

| Vector | Locally verified fact | Upstream-declared scenario and claim ceiling |
|---|---|---|
| `asqav-14-omitted-action-chain` | Both signatures and the hash link verify; the selected two-receipt slice is `act_1 → act_3` and contains no `act_2` receipt. | Upstream declares that `act_2` never reached the signer. The local two-receipt evidence does **not** independently prove that scenario fact, global capture completeness, or whether another signer observed `act_2`. |
| `asqav-15-unsigned-gap` | Both signatures and the hash link verify; the signed receipt carries `unsigned_gap.count == 2` and string `from`/`to` values. | Upstream interprets the marker as evidence of a signer outage. The local verifier proves the signed marker exists; it does **not** independently prove the outage cause, policy evaluation, or execution of the missing actions. |
| `asqav-16-chain-emission-blocked` | Both signatures and the hash link verify; the signed lifecycle record is `deny / chain_emission_blocked`. | The record makes the declared blocked interval visible. Reading it as proof that no external effect escaped still requires an independently justified non-bypassable enforcement point. |

This matches the OpenPoC-01 boundary:

> A verifier may correctly accept every receipt it was given while the stronger
> claim, “every relevant real-world effect was captured,” remains unsupported.

## Reproduce

```bash
python -m pip install -e '.[dev]'

git clone https://github.com/jagmarques/asqav-sdk /tmp/asqav-sdk
git -C /tmp/asqav-sdk checkout \
  17c814f9e2e51f005faa707d44adec0316534da8

python -m openpoc.asqav_upstream_binding \
  examples/asqav-selective-omission \
  /tmp/asqav-sdk

python -m openpoc.asqav_omission_compat \
  examples/asqav-selective-omission \
  --write /tmp/asqav-report.json

diff -u docs/asqav-selective-omission-compatibility.json \
  /tmp/asqav-report.json

python -m pytest -q tests/test_asqav_omission_compat.py
```

## Exact subject

- Upstream repository: `jagmarques/asqav-sdk`
- Upstream commit: `17c814f9e2e51f005faa707d44adec0316534da8`
- Upstream manifest: `verifier/conformance-vectors/manifest.json`
- Upstream lock: `verifier/conformance-vectors/manifest.lock.json`
- Selected vectors: 14, 15, and 16 only
- Locally frozen files: 10
- Compared upstream raw paths: 12
- Compared manifest records: 3
- Compared manifest-lock records: 12
- Signature algorithm exercised: Ed25519
- Chain rule exercised: SHA-256 of the predecessor payload's selected-corpus JCS bytes

## Claim boundary

This is **not** a complete independent implementation of the Asqav verifier and
does not score the rest of the Asqav corpus. It does not prove the upstream
draft correct, prove global capture completeness, independently establish the
real-world causes described by upstream scenario notes, certify a deployment,
or imply endorsement in either direction.

The result is narrower and more useful: the exact source files are bound to a
specific upstream commit, the receipt-level results agree for the three selected
vectors, and the report keeps locally verified facts separate from upstream-
declared scenario semantics.
