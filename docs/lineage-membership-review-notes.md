# Lineage Membership v0.1 — review notes

## Decision

The existing rolling lineage root remains unchanged. Selective historical
disclosure is implemented as a companion Merkle commitment over cycle
commitments that were first validated against the complete retained accumulator
chain.

## Why a second commitment is necessary

A linear hash chain is excellent for incremental tamper evidence, but proving an
old element requires the suffix from that element to the current tip. Trying to
hide the suffix while retaining the same primitive would either weaken the claim
or smuggle unverified history into a new receipt.

The profile therefore separates:

```text
active rolling commitment
        ≠
historical membership commitment
```

## Review priorities

Reviewers should focus on:

1. whether anchor construction really rejects a discontinuous cycle chain;
2. whether every selected-cycle field is recomputed rather than trusted;
3. whether leaf position is bound to the one-based cycle index;
4. whether odd-level duplicate-last behavior is unambiguous;
5. whether path length, side, and tree size are enforced;
6. whether the anchor is bound to the current accumulator and current cycle;
7. whether provider evidence or undisclosed cycle objects leak into the package;
8. whether the claim boundary clearly separates structural membership from anchor authenticity.

## Tested attacks

The regression suite covers:

- wrong membership root;
- proof rebound to another anchor;
- cycle-index and leaf-index substitution;
- sibling digest and side substitution;
- path truncation and extension;
- odd final-leaf duplicate substitution;
- disclosed reconciliation tampering;
- cycle-summary and commitment tampering;
- selected accumulator tampering;
- current accumulator/root tampering;
- reordered, incomplete, or non-tip retained history;
- zero contract identities;
- full-history and provider-evidence leakage.

## Explicit non-claim

The Merkle anchor is not automatically authoritative merely because its structure
validates. Production claims that require authority, freshness, or non-equivocation
must bind the anchor to an external signature, attestation, transparency log, or
another explicitly verified control plane.
