# T-Trace Repeated Witness-Policy Handoff Chain Profile v0.1

**Status:** Draft profile  
**Scope:** fixed-shape continuity for repeated witness-policy rotations

## 1. Purpose

The Witness-Set Rotation / Quorum-Handoff profile proves one direct policy transfer:

```text
old active quorum
        ↓
old-policy handoff quorum
        ↓ same exact handoff statement
new-policy handoff quorum
        ↓
new-policy activation quorum
```

A valid direct handoff does not by itself tell a relying party whether a later handoff
was appended to the policy history it previously accepted. Without an authenticated
chain tip, a party may be shown:

- a rollback to an older policy epoch;
- a replay of an already consumed handoff;
- a skipped policy epoch;
- a shorter but individually valid policy history;
- two different direct successors of one accepted policy tip.

This profile adds a fixed-shape rolling chain reference above the existing handoff
package. The direct handoff verifier remains unchanged.

## 2. Fractal Causal Refactoring diagnosis

The visible failure is repeated policy rotation. The first meaningful divergence is
not inside one handoff certificate. It is the distinction between local transition
validity and chain validity:

```text
one valid handoff
        ≠
one valid extension of the exact previously accepted handoff chain
```

Relaxing the single-handoff verifier would erase the predecessor boundary. The repair
therefore adds a separate chain object that commits the exact old activation package,
new activation package, prior chain reference, and prior chain root.

## 3. Layering

```text
Witness-Quorum Anchor
        ↓
Witness-Set Rotation / Dual-Quorum Handoff
        ↓
Repeated Witness-Policy Handoff Chain
```

Membership roots, lineage accumulators, producer statements, witness observations,
and direct handoff certificates are unchanged.

## 4. External authentication boundary

The first chain step requires an externally pinned genesis policy digest and epoch.
Every later step requires the exact previous chain reference, or an independently
authenticated digest of it.

The chain does not make stale data fresh. A structurally valid older tip remains an
older tip. Rollback and truncation resistance require the relying party to remember or
otherwise authenticate the latest accepted chain reference.

## 5. Handoff-chain step commitment

Each step commits:

```text
chain ID and handoff index
policy ID
old and new policy epochs/digests
old active quorum package/certificate
new activation quorum package/certificate
complete handoff package/certificate
producer statement and membership view
previous chain reference/root
chain and authorization contracts
```

The handoff package is independently verified before its digests enter the step.

For step `n > 1`:

```text
old_active_quorum_package[n]
==
new_activation_quorum_package[n-1]
```

The corresponding active quorum certificate must also match byte-for-byte.

This is stricter than accepting another independently valid quorum under the same
policy. It makes the accepted activation package itself the causal predecessor.

## 6. Fixed-shape chain reference

`WitnessPolicyHandoffChainRef` has exactly eighteen scalar fields:

```json
{
  "schema": "ttrace-witness-policy-handoff-chain-ref/v0.1",
  "chain_id": "example.procurement.witness-policy-chain",
  "policy_id": "lineage-witness-set",
  "genesis_policy_epoch": 1,
  "genesis_policy_sha256": "...",
  "completed_handoffs": 3,
  "current_policy_epoch": 4,
  "current_policy_sha256": "...",
  "current_activation_package_sha256": "...",
  "current_activation_certificate_sha256": "...",
  "current_handoff_package_sha256": "...",
  "current_handoff_certificate_sha256": "...",
  "previous_chain_ref_sha256": "...",
  "previous_chain_root_sha256": "...",
  "step_commitment_sha256": "...",
  "chain_root_sha256": "...",
  "chain_contract_sha256": "...",
  "authorization_contract_sha256": "..."
}
```

The chain root is the canonical SHA-256 digest of every non-root field under
`ttrace-witness-policy-handoff-chain-root-input/v0.1`.

The active reference therefore remains fixed-shape after one, three, or many handoffs.
Complete historical handoff packages remain external proof material.

## 7. Continuity invariants

A valid advance requires all of the following:

1. the previous chain reference is exact-shape and self-bound;
2. chain ID, policy ID, genesis policy, and contracts are unchanged;
3. the next handoff's old policy equals the previous current policy byte-for-byte;
4. the next old policy epoch equals the previous current epoch;
5. the next new policy epoch is exactly old epoch plus one;
6. the next old active quorum package equals the previous new activation package;
7. the next old active certificate equals the previous new activation certificate;
8. `completed_handoffs` advances by one;
9. the new step binds the exact previous chain reference and chain root;
10. the new chain root binds every active field.

For a chain beginning at policy epoch `g`:

```text
current_policy_epoch = g + completed_handoffs
```

## 8. Complete-chain verification

A complete-chain verifier rebuilds the seed from the externally expected genesis
policy and then advances through every supplied handoff package.

The rebuilt tip must be byte-identical to the externally expected active chain
reference.

This rejects:

- reordered packages;
- omitted intermediate handoffs;
- packages beginning from a later policy presented as the original genesis;
- a truncated chain compared with a pinned later tip.

## 9. Direct-successor fork evidence

Given one exact previous chain reference, two independently valid but semantically
different direct successors produce bounded fork evidence containing:

- the exact previous chain reference/root;
- the old policy epoch/digest;
- both candidate chain references/roots;
- both candidate new policy digests;
- both candidate handoff package digests.

This proves a fork only for the two supplied direct successors of the same pinned tip.
It does not prove that no undisclosed successor exists.

Serialized fork evidence is never trusted on shape alone. The standalone verifier
requires the pinned predecessor and both candidate handoff packages, revalidates both
direct successors, rebuilds the canonical evidence, and compares exact bytes.

## 10. Fail-closed conditions

The reference implementation rejects at least:

- malformed or extended step, chain-reference, receipt, or fork-evidence shapes;
- Python booleans used as epochs or handoff counts;
- zero current-policy, package, certificate, contract, step, or root digests;
- a seed that does not match the externally pinned genesis policy;
- policy ID or policy digest drift;
- rollback, replay, or skipped epoch;
- a valid handoff built from a different old active quorum package;
- a valid handoff whose old active certificate is not the previous activation
  certificate;
- previous-chain reference/root tampering;
- contract drift through replacement of the pinned predecessor;
- reordered, truncated, or unrelated full histories;
- an expected tip that differs from the rebuilt chain;
- fork comparison when either candidate is not a valid direct extension;
- Boolean seed epochs passed through the public agreement validator;
- serialized fork evidence that cannot be independently recomputed.

## 11. Assurance boundary

A successful result establishes for the supplied externally verified handoff evidence
and pinned predecessor/genesis:

- exact policy-epoch continuity;
- exact activation-package carry-forward;
- a fixed-shape rolling chain commitment;
- deterministic rebuild of the supplied complete chain;
- bounded evidence for two supplied conflicting direct successors.

It does not by itself establish:

- freshness when a relying party did not pin a prior tip;
- global non-equivocation;
- discovery of undisclosed chain forks;
- witness honesty, independence, or key security;
- signature verification when external verification was skipped;
- emergency policy recovery;
- Byzantine consensus;
- transparency-log or gossip completeness;
- zero knowledge.

Accordingly:

```text
conditional_handoff_chain_status = pinned-predecessor-handoff-chain-verified
global_non_equivocation_status   = unproven
```

## 12. Reference implementation

- implementation: `ttrace/lineage_witness_handoff_chain.py`
- tests: `tests/test_lineage_witness_handoff_chain.py`
- executable verifier: `scripts/verify_witness_policy_handoff_chain.py`
- predecessor profile: `spec/witness-set-rotation-handoff-profile-v0.1.md`

## 13. Next falsifiable gate

**Witness-Policy Handoff-Chain Membership / Selective Disclosure v0.1** — prove that a
selected historical policy rotation belongs to the current handoff-chain root without
revealing every intermediate handoff package.
