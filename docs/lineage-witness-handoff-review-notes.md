# Witness-Policy Handoff Review Notes

## First meaningful divergence

The same-policy verifier intentionally rejects policy drift. The handoff must not
weaken that guard. It adds a separate four-stage acceptance topology around one exact
lineage view.

## Review focus

Reviewers should challenge:

1. exact equality of old/new active producer statements, anchors, and accumulators;
2. policy-ID continuity and strict `old_epoch + 1 == new_epoch` semantics;
3. exact handoff binding to both canonical policy digests;
4. role-certificate witness selection, ordering, threshold, policy authorization, and complete coverage of every handoff observation;
5. old active → old handoff witness predecessor continuity;
6. new handoff → new activation witness predecessor continuity;
7. whether disjoint old/new witness sets still receive genuine dual authorization;
8. conflict attribution only within one exact old-policy and producer-view context;
9. whether the wording overstates signature verification, witness honesty, Byzantine
   safety, or global non-equivocation.

## Independent fixture lanes

The pytest fixture and executable verifier construct their lineage endpoints and
handoff packages separately. Some duplication is deliberate so one faulty shared
fixture builder does not make both lanes agree.

## Non-claim to preserve

`no_unprotected_acceptance_gap = true` applies only to the supplied exact four-stage
handoff and authenticated external evidence. It does not imply that all network
participants observed the handoff, that witnesses are honest, or that rollback to an
old policy is globally impossible.
