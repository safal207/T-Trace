# Repeated lineage compaction — review notes

This change extends the merged Portable Causality Profile with a bounded active-lineage commitment for repeated two-parent reconciliation.

## Review focus

Please verify that:

1. every new cycle first passes the existing fail-closed two-parent reconciliation validator;
2. the accumulator has an exact, constant 13-field shape;
3. the rolling root binds every non-root field;
4. cycle 1 uses zero predecessor digests and later cycles require non-zero predecessors;
5. the next common state must equal the previous active state digest;
6. the compaction receipt is recomputed and uses an exact key set;
7. provider, authority, and provenance identities do not enter portable active objects;
8. the claim boundary does not imply selective historical membership proofs or authenticated storage.

## Intended verification

```text
base T-Trace validator
portable causality example
three-cycle lineage verifier
full pytest suite
Governex -00/-01 interoperability
CodeQL
Gitleaks
```

## Claim boundary

The profile provides a rolling commitment to externally retained proof history. It does not prove that external history remains available, that an unsigned accumulator is authentic, or that a selected hidden cycle belongs to the root without a separate membership proof.
