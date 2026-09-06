# Witness-Policy Handoff-Chain Membership v0.1 — Review Notes

## Decision

The existing rolling handoff-chain reference remains unchanged. Selective
historical disclosure is implemented as a companion, domain-separated Merkle
commitment over step commitments that were first reproduced from a complete,
validated handoff chain.

The disclosure contains one complete selected handoff package and one fixed-shape
predecessor chain reference. It does not contain the intervening handoff packages.

## Why a second commitment is necessary

The rolling chain root is efficient active state, but proving an old step from it
requires the suffix from that step to the current tip. The protocol keeps the jobs
separate:

```text
active rollback-resistant tip commitment
        ≠
selective historical membership commitment
```

The Merkle root is a companion index, not a replacement chain root and not something
that can be inferred from the rolling root alone.

## Highest-risk review properties

### 1. Anchor construction validates history

The builder must not accept arbitrary step digests or caller-supplied intermediate
records. It accepts the ordered complete packages, deterministically rebuilds the
seed and every later chain advance at contiguous indexes, and requires the final
derived reference to equal the supplied current tip byte-for-byte.

### 2. The selected direct edge is independently reproduced

For index `1`, `previous_chain_ref` must be exactly null and seed inputs must come
from the anchor context. For later indexes, the disclosed predecessor must be a
valid fixed-shape reference at exactly `index - 1`.

The existing chain API must then reproduce both the disclosed `chain_step` and
`chain_ref` byte-for-byte from the selected complete handoff package.

### 3. The membership root is current-tip-bound

The anchor binds the exact current chain-reference digest, rolling root, and current
step commitment. A second sibling path proves that current step as the final Merkle
leaf. Tree-size equality without this final-step path is insufficient because a
same-size tree could omit the actual tip.

### 4. Domain separation and positional binding are exact

Review that:

- handoff membership leaves and nodes have distinct schemas;
- the leaf binds one-based `handoff_index` to `step_commitment_sha256`;
- `leaf_index == handoff_index - 1`;
- path length, side, and duplicate-last behavior are deterministic;
- proof and anchor schemas reject unknown fields.

### 5. Privacy is history-level, not evidence-level

The selected handoff package intentionally includes its intrinsic witness and
authority evidence and is revalidated in full. The implementation must not apply a
recursive ban to legitimate witness IDs, observations, statements, or certificates.

What is excluded is the full chain history: all other handoff packages and all
intermediate steps/references except the one direct predecessor reference needed to
reproduce the selected edge.

### 6. Authorization planes and claim boundary remain explicit

The anchor copies `chain_contract_sha256` from the current chain reference and
copies its `authorization_contract_sha256` under the unambiguous anchor alias
`chain_authorization_contract_sha256`. Separate
`membership_contract_sha256` and `authorization_contract_sha256` fields bind the
companion membership semantics and its authorization plane. Review must ensure all
four are non-zero, cannot be substituted for one another, and remain bound through
the exact anchor digest.

Structural validation of an unsigned anchor is not authority, freshness, or global
non-equivocation.

The reference decision therefore exposes anchor authorization and current-tip
freshness as `not-evaluated`; it must not emit the handoff-chain profile's
`pinned-predecessor-handoff-chain-verified` status without a separate external
trust input.

## Falsification cases

Regression coverage should reject:

- wrong/extra schemas or fields and excessively nested objects;
- Boolean, floating-point, zero, negative, or out-of-range indexes;
- anchor rebound to another current chain reference;
- current root, current step, genesis, policy, chain-contract,
  chain-authorization, membership-contract, or membership-authorization drift;
- proof rebound to another anchor;
- handoff/leaf index substitution;
- sibling digest, side, order, truncation, or extension mutations;
- invalid odd-level duplicate-last siblings;
- a same-size membership tree that omits the actual current step;
- a null later predecessor or a non-null seed predecessor;
- a predecessor at the wrong completed-handoff count;
- selected package, step, reference, or commitment substitution;
- a selected final reference different from the supplied current tip;
- arbitrary step-digest input or discontinuous/non-tip history at anchor construction;
- full-history fields outside the selected package;
- recursion-bomb inputs.

Boundary cases should include one handoff, power-of-two tree sizes, odd tree sizes,
selection of the seed, selection of a middle handoff, and selection of the current
handoff.

## Explicit non-claims

A valid disclosure proves one revalidated handoff step belongs to one supplied
current-tip-bound membership anchor. It does not prove:

- anchor authenticity without an external signature or attestation;
- freshness without a pinned or independently authenticated current tip;
- append-only consistency between two membership anchors;
- global non-equivocation or discovery of undisclosed forks;
- validity of every hidden handoff as independently checked by the selective verifier;
- witness honesty, key security, transparency publication, capture completeness, or
  zero-knowledge privacy.

Review language should preserve `global_non_equivocation_status = unproven`.
