# Portable causality examples

`two-parent-reconciliation.json` is generated deterministically by:

```bash
python scripts/verify_portable_causality.py \
  examples/portable-causal/two-parent-reconciliation.json \
  --write
```

Verify the committed bytes with:

```bash
python scripts/verify_portable_causality.py \
  examples/portable-causal/two-parent-reconciliation.json
```

The example demonstrates:

- one common causal tip at epoch 2;
- two different semantic branch states at epoch 3;
- exact branch-bound votes;
- a canonical order-independent two-parent reconciliation at epoch 4;
- absence of provider, signer, and evidence identities from the portable reconciliation result.

The example uses deterministic placeholder evidence digests. It does not claim live cryptographic attestation.
