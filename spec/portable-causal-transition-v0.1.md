# T-Trace Portable Causal Transition Profile v0.1

**Status:** Draft normative profile  
**Depends on:** Portable Causal State Profile v0.1

## 1. Purpose

A portable transition identifies the semantic movement between two portable state references without promoting the concrete evidence path into transition identity.

The central distinction is:

```text
CausalTransitionRef            = portable semantic transition identity
historical transition evidence = provider-specific proof of that transition
```

## 2. `CausalTransitionRef`

```json
{
  "schema": "ttrace-causal-transition-ref/v0.1",
  "trust_domain": "ttrace.authorization",
  "logical_state_id": "purchase-42",
  "logical_transition_id": "approve-next-policy",
  "from_causal_epoch": 2,
  "to_causal_epoch": 3,
  "from_state_ref_sha256": "<sha256>",
  "to_state_ref_sha256": "<sha256>",
  "transition_contract_sha256": "<sha256>",
  "authorization_contract_sha256": "<sha256>"
}
```

## 3. Invariants

A conforming transition MUST satisfy all of the following:

1. source and target belong to the same `trust_domain`;
2. source and target share the same `logical_state_id`;
3. `to_causal_epoch = from_causal_epoch + 1`;
4. source and target semantic state digests differ;
5. source and target references are committed by exact SHA-256 digest;
6. the transition contract and authorization contract are explicitly committed;
7. concrete provider, signer, registry, manifest, and history-generation identities remain evidence rather than portable transition identity.

A semantic no-op in one historical path MUST NOT be represented as a portable causal transition.

## 4. Object validity and chain validity

A verifier MUST distinguish:

```text
object validity = this transition/checkpoint has a valid local shape
chain validity  = every predecessor link reaches the accepted anchor
```

Validating only the current object and one predecessor is insufficient for later epochs when the predecessor itself depends on earlier context.

A full-chain verifier SHOULD validate the complete retained checkpoint and witness prefix back to an accepted anchor or to an explicitly trusted compaction receipt.

## 5. Evidence path independence

Two evidence paths MAY use different:

- providers;
- signers;
- historical generation schedules;
- registry or manifest layouts;
- execution environments;
- artifact representations.

They establish the same portable transition only when they independently prove the same source state, target state, logical transition, and governing contracts.

## 6. Fail-closed conditions

A verifier MUST reject:

- epoch gaps;
- source or target state mismatch;
- logical transition mismatch;
- transition-contract mismatch;
- authorization-contract mismatch;
- broken historical continuity;
- raw evidence identity smuggled into a portable logical field;
- a claimed transition whose semantic state did not change.

## 7. Claim boundary

This profile defines transition identity and continuity rules. It does not define the domain policy that decides whether a transition is desirable, legal, safe, or sufficiently authorized.
