# Repeated Witness-Policy Handoff Chain — Review Notes

## First meaningful divergence

A direct handoff verifier answers whether one policy transition is valid. It does not
answer whether that transition extends the exact chain tip a relying party already
accepted. This PR adds a separate rolling chain object and does not weaken the merged
single-handoff verifier.

## Review focus

Reviewers should challenge:

1. exact carry-forward of the previous new-activation package and certificate;
2. strict JSON integer handling for genesis/current epochs and handoff counts;
3. the invariant `current_epoch = genesis_epoch + completed_handoffs`;
4. seed binding to an externally expected genesis policy digest;
5. exact previous chain-reference/root binding;
6. whether every non-root active field is bound by `chain_root_sha256`;
7. fixed eighteen-field active shape and absence of nested raw history;
8. rejection of rollback, replay, skipped epoch, reorder, and truncation;
9. fork evidence only for two supplied valid direct successors of one exact tip;
10. wording that might be misread as freshness, global non-equivocation, gossip
    completeness, witness honesty, or cryptographic verification by T-Trace core.

## Independent verification lanes

The focused pytest suite uses deterministic fixture builders and adversarial
mutations. The executable verifier independently constructs three real dual-quorum
handoffs, rebuilds the chain, and constructs a conflicting direct successor.

## Non-claim to preserve

A stale but structurally valid chain tip remains stale. Rollback resistance is only
supported when the relying party pins or independently authenticates the latest
accepted predecessor. The chain cannot discover an undisclosed fork by itself.
