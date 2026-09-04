# Asqav selective-omission cross-verification

## Result

`3/3 AGREE` for three frozen Asqav-native vectors at upstream commit
`17c814f9e2e51f005faa707d44adec0316534da8`.

The independent verifier:

- binds ten source files by byte length, SHA-256, and Git blob ID;
- reconstructs the selected JCS payload bytes without importing Asqav code;
- verifies six Ed25519 signatures (predecessor and successor for each vector);
- rederives all three `previousReceiptHash` links;
- checks the vector-specific semantic marker;
- emits a deterministic machine-readable report;
- includes negative controls for signed-payload mutation, chain mutation,
  non-integer canonicalization, and raw-file tampering.

Machine-readable result:
[`asqav-selective-omission-compatibility.json`](./asqav-selective-omission-compatibility.json)

Verifier:
[`openpoc/asqav_omission_compat.py`](../openpoc/asqav_omission_compat.py)

Frozen inputs and pins:
[`examples/asqav-selective-omission/`](../examples/asqav-selective-omission/)

## What agrees

| Vector | Wire result | Capture-side reading |
|---|---|---|
| `asqav-14-omitted-action-chain` | Both signatures and the hash link verify. | The valid chain is silent about `act_2`, which never reached the signer. Receipt integrity does not establish capture completeness. |
| `asqav-15-unsigned-gap` | Both signatures and the hash link verify; `unsigned_gap.count == 2`. | The signed marker establishes a signer outage interval. It does not establish that the two unsigned actions were policy-evaluated or executed. |
| `asqav-16-chain-emission-blocked` | Both signatures and the hash link verify; the lifecycle record is `deny / chain_emission_blocked`. | The blocked interval becomes visible after emission resumes. Treating that as proof that no effect escaped still requires an independently justified non-bypassable enforcement point. |

This matches the OpenPoC-01 boundary:

> A verifier may correctly accept every receipt it was given while the stronger
> claim, “every relevant real-world effect was captured,” remains unsupported.

## Reproduce

```bash
python -m pip install -e '.[dev]'
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
- Frozen files: 10
- Signature algorithm exercised: Ed25519
- Chain rule exercised: SHA-256 of the predecessor payload's selected-corpus JCS bytes

## Claim boundary

This is **not** a complete independent implementation of the Asqav verifier and
does not score the rest of the Asqav corpus. It does not prove the upstream
draft correct, prove global capture completeness, certify a deployment, or
imply endorsement in either direction.

The result is narrower and more useful: the two implementations agree on the
three omission/recovery boundaries that motivated the exchange, and the report
keeps record validity, outage evidence, effect prevention, and capture
completeness separate.
