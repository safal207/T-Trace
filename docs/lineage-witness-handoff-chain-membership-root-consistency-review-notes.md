# Handoff Membership-Root Consistency v0.1 — Review Notes

## Review target

This layer connects two already-defined objects:

```text
validated repeated handoff history
        -> membership anchor at size m
        -> compact append-only proof
        -> membership anchor at size n
```

The review target is narrower than full rolling-chain verification. The compact
proof establishes prefix preservation between membership roots and binds the last
leaf at each endpoint. It intentionally does not replay hidden handoff packages.

## Security decisions

### Handoff hash domains are reused exactly

The compact frontier uses the leaf and node functions from the handoff-chain
membership module. Reusing lineage-cycle Merkle domains would produce a formally
well-shaped proof for the wrong commitment universe.

### Both endpoint tips need membership paths

Root extension alone does not prove that an anchor's declared current step is the
last leaf of its tree. Separate old and new current-step paths close that binding.
For odd-width levels, the verifier also checks that a duplicate-last sibling equals
the current node.

### Prefix and rolling descendance are different claims

The builder sees the retained histories, so it verifies both the commitment prefix
and the canonical old boundary reference inside the later history. A standalone
consumer sees only compact subtree hashes. Its success status therefore says
`rolling_chain_descendance_status=not-independently-proven`.

### Four contract planes remain distinct

The comparison context contains:

1. handoff-chain contract;
2. handoff-chain authorization contract;
3. membership contract; and
4. membership-anchor authorization contract.

None is treated as an alias for another. A mismatch in any plane rejects root
consistency and prevents an equivocation comparison from being attributed across
contexts.

### Authority continuity is an explicit second layer

Structural consistency does not imply that an authority endorsed either anchor.
The normalized statement binds the anchor digest, membership root, exact current
reference digest, current chain root, current step, current policy, genesis, tree
algorithm, and all contracts. Direct continuity requires adjacent sequences and an
exact predecessor digest.

### Equivocation evidence is recomputed, not shape-checked

The detector can emit a not-proven diagnostic for a nonconflicting or
noncomparable pair. The standalone evidence validator accepts only a regenerated
actual conflict whose canonical bytes equal the supplied evidence. This prevents a
`verified: true` diagnostic from being reinterpreted as proof of equivocation.

## Fail-closed cases covered

The regression suite exercises:

- singleton, power-of-two, and odd-width trees;
- independent golden leaf, node, frontier, append, and root vectors;
- exact package, endpoint, proof, block, path, statement, and evidence shapes;
- boolean and floating-point values in proof sizes and block coordinates;
- missing, extra, reordered, misaligned, and tampered frontier/append blocks;
- tampered endpoint anchor digests and current-step paths;
- noncanonical odd-leaf duplication;
- same-size, rollback, non-tip, and different-prefix builder inputs;
- foreign chain context and membership-contract migration;
- statement authority, sequence, predecessor, provenance, and unknown-field errors;
- same-sequence and same-size-root conflicts;
- different-authority noncomparability;
- exact standalone evidence recomputation, tampering, and identical-input rejection;
- excessive nesting; and
- root-package export uniqueness plus real star import.

## Residual assumptions

The verifier consumes supplied endpoints. It does not discover a newer tip or a
conflicting view. Authority statement provenance is declared as already verified;
signature or quorum mechanics belong to the layer that constructs that assertion.
The evidence detector is complete only for the pair supplied to it.

## Operational gate

Before merge, the branch should pass:

```text
focused adversarial tests
new executable consistency verifier
all earlier protocol verifier scripts
full pytest suite
public star-import regression
format and whitespace checks
independent code/spec review
fresh exact-head CI and security checks after publication
```

## Follow-on layer

Witness-Policy Handoff Membership-Root Gossip / Split-View Detection v0.1 should
define how independent observers exchange and retain statements so conflicting
views are more likely to meet. It must not upgrade observation coverage into a
claim of universal completeness.
