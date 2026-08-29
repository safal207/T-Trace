# T-Trace Specifications

This directory contains the normative and draft protocol specifications for T-Trace.

## Specifications

- [`t-trace.md`](t-trace.md) — T-Trace v0.1 base specification for append-only acknowledged state transitions.
- [`causal-execution-graph-v0.1.md`](causal-execution-graph-v0.1.md) — draft distributed execution profile for causal ordering, retries, re-resolution, fork/merge, recovery, and portable verification.
- [`portable-causality-profile-v0.1.md`](portable-causality-profile-v0.1.md) — draft canonical identity profile for semantic state, transitions, genuine forks, and explicit two-parent reconciliation.
- [`lineage-compaction-profile-v0.1.md`](lineage-compaction-profile-v0.1.md) — draft fixed-shape rolling commitment for repeated fork/reconciliation cycles.
- [`lineage-membership-profile-v0.1.md`](lineage-membership-profile-v0.1.md) — draft Merkle membership profile for selective disclosure of one historical reconciliation cycle without revealing every intervening cycle.
- [`membership-root-consistency-profile-v0.1.md`](membership-root-consistency-profile-v0.1.md) — draft compact append-only consistency proof between two membership roots with bounded presented-view equivocation evidence.
- [`witness-quorum-anti-equivocation-profile-v0.1.md`](witness-quorum-anti-equivocation-profile-v0.1.md) — draft threshold-witness acceptance layer for exact lineage-anchor statements, direct intersecting-witness continuity, and attributable supplied-view double-signing evidence.
- [`witness-set-rotation-handoff-profile-v0.1.md`](witness-set-rotation-handoff-profile-v0.1.md) — draft dual-quorum handoff profile that rotates one authenticated witness policy into the next without an unprotected acceptance gap.
- [`repeated-witness-policy-handoff-chain-profile-v0.1.md`](repeated-witness-policy-handoff-chain-profile-v0.1.md) — draft fixed-shape rolling chain for multiple verified witness-policy handoffs with pinned predecessor continuity, rollback rejection, and direct-successor fork evidence.

## Layering

```text
T-Trace v0.1 record envelope
        ↓
Causal Execution Graph Profile
        ↓
Portable Causality Profile
        ↓
Repeated Lineage Compaction Profile
        ↓
Lineage Membership / Selective Disclosure Profile
        ↓
Membership-Root Consistency / Presented-View Anti-Equivocation Profile
        ↓
Witness-Quorum Anchor / Conditional Non-Equivocation Profile
        ↓
Witness-Set Rotation / Dual-Quorum Handoff Profile
        ↓
Repeated Witness-Policy Handoff-Chain Consistency Profile
```

The base validator remains unchanged. Profiles add domain payload semantics and focused verifiers without silently changing T-Trace v0.1 wire compatibility.

## Core principles

> **A portable execution record is a causally ordered execution graph, not a linear audit log.**
>
> **Evidence proves a causal state; evidence does not become the causal state's portable identity.**
>
> **Active causal identity and complete audit ancestry are different objects.**
>
> **A rolling lineage commitment and a historical membership index serve different verification jobs.**
>
> **Append-only consistency is a relation between roots, while global non-equivocation requires comparing independently observed authority statements.**
>
> **A producer statement is structural authority evidence; an intersecting witness quorum is a separate acceptance layer.**
>
> **Witness-quorum safety is conditional on authenticated policy and witness evidence and does not prove global non-equivocation.**
>
> **A witness-policy digest must not change by ordinary continuity; rotation requires one exact view accepted by both the old and the new policy.**
>
> **A valid policy handoff is one edge; rollback-resistant policy history requires a separately pinned handoff-chain tip.**

The distributed profiles distinguish:

- logical operation from concrete execution attempt;
- wall-clock description from causal authority;
- provider evidence from portable semantic identity;
- historical generation from causal epoch;
- one-parent transition from multi-parent reconciliation;
- bounded active lineage from externally retained full proof history;
- rolling tamper evidence from selective historical membership proofs;
- structural root extension from authority-statement comparison;
- producer statement continuity from threshold witness acceptance;
- presented conflict detection from global non-equivocation;
- conditional quorum-intersection evidence from Byzantine-consensus claims;
- same-policy witness continuity from explicit dual-policy handoff authorization;
- one valid policy handoff from a pinned, rollback-resistant handoff chain.
