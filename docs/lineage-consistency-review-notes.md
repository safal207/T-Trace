# Membership-Root Consistency v0.1 — review notes

## Review target

This change adds a compact append-only consistency proof over the existing
`pairwise-duplicate-last-sha256/v0.1` lineage-membership roots.

It intentionally does not introduce a second authoritative root.

## Highest-risk properties

### 1. Frontier reconstruction

The old compact frontier must deterministically reconstruct the exact old
membership root.

Review:

- canonical prefix block shape;
- block alignment and contiguity;
- right-to-left duplicate-last bagging;
- single-leaf and power-of-two boundary cases.

### 2. Suffix coverage

`append_blocks` must cover exactly `[old_tree_size, new_tree_size)`.

Review:

- no gaps, overlaps, omissions, duplication, or reordering;
- power-of-two alignment;
- binary carry when equal terminal blocks merge;
- final frontier shape for the exact new tree size.

### 3. Endpoint current-tip binding

Both endpoint current cycle commitments must be proven members of their supplied
membership roots.

This is a separate requirement from frontier consistency. A proof that only
connects two opaque roots must not be allowed to pair an unrelated current
accumulator with either endpoint.

### 4. Authority statement boundary

`LineageAnchorStatement.verified` is a normalized result from an external
cryptographic verifier or attestation verifier.

It is not itself a signature algorithm.

Review that:

- unverified statements fail closed;
- seed and successor predecessor rules are exact;
- direct successor sequence is `+1`;
- authority continuity is mandatory;
- tree algorithm, membership contract, and authorization contract are
  statement-bound;
- direct chain verification does not perform conflict comparison;
- the result does not claim global non-equivocation.

### 5. Equivocation evidence

Two statements are comparable only within the same authority, trust domain,
logical state, tree algorithm, membership contract, and authorization contract.

Review:

- same-sequence / same-predecessor conflicts;
- same-size / different-root conflicts inside one exact membership context;
- membership-contract migrations do not create false equivocation evidence;
- different authorities do not create attributable equivocation evidence;
- no-conflict means `not proven`, not global safety.

## Falsification cases

The test suite should reject:

- changed old frontier hash;
- changed append-block hash;
- missing or misaligned append block;
- changed old or new current-tip path;
- proof schema drift or extra fields;
- membership or authorization contract drift;
- same-size “extension”;
- a non-prefix later history;
- successor statement rebound to another predecessor;
- split-view statements from one authority.

## Claim boundary

A valid result proves append-only consistency relative to the supplied membership
anchors and normalized verified statements.

It does not prove:

- statement authenticity without the external verifier;
- global non-equivocation;
- transparency-log publication;
- witness availability;
- capture completeness;
- zero knowledge.
