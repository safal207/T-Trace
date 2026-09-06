# Witness-Quorum Profile Review Notes

## First meaningful divergence

The predecessor profile could compare two supplied producer statements, but producer
statements had no shared acceptance layer. The repair therefore adds a witness-quorum
certificate rather than changing membership-root identity.

## Review focus

Reviewers should concentrate on:

1. strict JSON integer handling for policy epoch, threshold, and observation sequence;
2. exact policy, observation, certificate, package, and evidence schemas;
3. `2 * threshold > authorized_witness_count` and the minimum-intersection formula;
4. observation binding to the exact producer statement and full membership context;
5. canonical witness ordering and duplicate rejection;
6. continuity of every witness appearing in both endpoint quorums;
7. split-view comparison only inside one exact witness-policy context;
8. whether overlapping witnesses are attributed only from supplied valid evidence;
9. whether any wording can be misread as global non-equivocation.

## Independent fixture lanes

The pytest fixture and executable verifier intentionally construct their retained
lineages separately. Some duplication is retained to reduce the chance that one
faulty shared fixture factory makes both verification lanes agree.

## Non-claim to preserve

A three-of-five certificate is not automatically a Byzantine-consensus proof.
Conditional safety still depends on an authentic policy, verified witness evidence,
and at least one honest, non-double-signing witness in every quorum intersection.

An overlapping witness is reported as a double signer only in the bounded sense that
the supplied valid packages show that witness authenticated both exact conflicting
producer statements. The profile does not infer motive, key custody, or global
behavior outside the supplied evidence.
