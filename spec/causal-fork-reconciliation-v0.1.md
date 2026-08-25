# T-Trace Causal Fork / Reconciliation Profile v0.1

**Status:** Draft normative profile  
**Depends on:** Portable Causal State Profile v0.1

## 1. Purpose

This profile defines one explicit two-parent fork and reconciliation construction.

A fork occurs when two independently verified branches descend from the same portable causal tip and establish different semantic states. A reconciliation occurs when both branch authorities bind their exact branch tips to one new authorized semantic state.

The central rule is:

> **A reconciliation is a DAG join, not a relaxed linear transition.**

Selecting one predecessor and forgetting the other is conflict selection, not reconciliation.

## 2. Fork branch identity

`ForkBranchRef` binds:

- exact common `CausalStateRef` digest;
- logical branch ID;
- branch `CausalStateRef` digest;
- fork epoch and branch epoch;
- branch contract;
- authorization contract.

Provider, signer, and evidence digest remain in a separate `BranchObservation`.

Each branch checkpoint binds the exact common checkpoint digest. Each branch witness binds the exact common witness digest and its branch checkpoint.

## 3. Independent branch observations

For the independence claim in this profile, the two accepted observations MUST use distinct:

- provider IDs;
- authority IDs;
- evidence digests;
- logical branch IDs;
- branch checkpoint identities;
- semantic state digests.

Profiles that do not require provider or authority independence MAY define a weaker assurance level, but MUST label it explicitly.

## 4. Reconciliation votes

Each branch authority produces a vote bound to:

- its exact branch ref;
- its exact branch state ref;
- its exact branch checkpoint;
- its exact branch witness;
- the target semantic state;
- reconciliation contract;
- reconciliation authorization contract.

Votes MUST agree on target and contracts. A vote for one branch MUST NOT be replayed against another branch.

## 5. Canonical two-parent set

The reconciliation reference contains two parent entries. Each parent commits:

- logical branch ID;
- branch-ref digest;
- state-ref digest;
- checkpoint digest;
- witness digest.

Parent entries are sorted by checkpoint digest before serialization. Therefore reversing input branch order MUST produce byte-identical portable reconciliation objects.

The two checkpoint digests MUST be distinct. A parent MUST NOT be omitted, duplicated, or replaced.

## 6. Reconciled state

The reconciled state:

- remains in the same trust domain and logical state;
- advances one causal epoch beyond the branch epoch;
- commits to a semantic state different from the common state and both branch states;
- is linked by a `CausalReconciliationRef` to the exact common tip and both exact branch tips.

The reconciliation checkpoint contains the sorted two-parent checkpoint set. The reconciliation witness contains the corresponding sorted two-parent witness set.

## 7. Portable receipt

A successful receipt reports at least:

```text
lineage_parent_count       = 2
both_lineages_preserved    = true
fork_semantics_divergent   = true
branch_order_canonical     = true
raw_evidence_embedded      = false
```

The receipt also commits the parent-set, reconciled state, reconciliation reference, checkpoint, and witness digests.

## 8. Fail-closed conditions

A conforming verifier MUST reject:

- unverified branch evidence;
- duplicate provider, authority, evidence, or logical branch identity when independence is claimed;
- non-divergent branch semantics;
- a branch not descending from the exact common tip;
- a vote rebound to another branch;
- target or contract disagreement;
- a target equal to the common state or either branch state;
- a missing, duplicated, or replaced parent;
- non-canonical parent ordering that changes bytes;
- raw provider, signer, or evidence identity embedded in portable reconciliation objects.

## 9. Non-goals

This version does not establish:

- arbitrary N-parent reconciliation;
- repeated or nested fork cycles;
- lineage compaction after repeated joins;
- Byzantine quorum correctness;
- automatic conflict-resolution policy safety;
- governance legitimacy.
