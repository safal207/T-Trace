# Controlled artifact handoff profile v0.1

Status: selected implementation contract. This profile reuses the existing
Governex -01 receipt signed-byte format and OpenPoC-03 comparison; it is not a
new signature envelope or a general claim of production completeness.

## 1. Question and roles

A sender exports one harmless artifact; a receiver imports it and issues its
own receipt. A later reviewer asks whether the presented, authenticated
declarations support that particular handoff at the chosen audit cutoff, and
whether their signers are authorized under the receiver's current policy.

Sender, receiver, and reviewer are distinct responsibilities. Different test
keys/processes on one maintainer's machine do not constitute independent
organizations or an external pilot. A signed success declaration does not
prove all real-world effects, absence of bypass paths, or truth of its clock.

## 2. Exact input boundary

The package is a flat directory with `manifest.json`, `artifact.bin`, and zero
or one `sender.jsonl` and `receiver.jsonl`. Other paths, links, nonregular files,
and unknown versions/fields are rejected. No archive extraction is supported.
The receiver context is a separate explicit file outside the package. Location
separation is enforced but cannot itself prove independent provenance.

Manifest fields are exactly `schema`, `profile`, `correlation_id`, `files`.
`schema` is `ttrace.artifact-handoff-package/v1`; `profile` is
`ttrace.artifact-handoff/v1`. `files` contains exactly the supplied artifact
and receipt filenames, each with exact `bytes` and `sha256` fields. SHA-256 is
64 lowercase hexadecimal characters. Integrity against this manifest means
self-consistency, not publisher authentication.

Artifact size is 1..1,048,576 bytes. Each receipt is at most 16,384 bytes and is
exactly one JSON object line followed by LF, with no CR or extra LF. Preserve
those original bytes; the observation digest covers the complete file,
including its final LF. Metadata/context is at most 131,072 bytes, JSON nesting
at most 12, with duplicate keys, nonfinite numbers, and fractional/exponent
number syntax rejected. All integers must be in the safe exact range
0..9,007,199,254,740,991 before field-specific bounds. Booleans are not integers.

Identifiers match `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`. Dates are integer Unix
milliseconds, 0..4,102,444,800,000. Epochs are integers 1..2,147,483,647.
These intentionally restricted values make the selected cross-language
canonicalization contract explicit; they do not claim arbitrary JSON/JCS support.

## 3. Native signed statements

Each receipt has exactly `step_id`, `action_id`, `params`, `success`, `ts_ms`,
`seq`, `public_key`, `signature`. `seq` is exactly integer zero: these are two
separate single-receipt genesis logs, not a claimed inter-party history chain.
Step IDs are distinct. Public keys are 32 raw Ed25519 bytes as lowercase hex;
signatures are 64 bytes as lowercase hex. No unsigned extensions are admitted.

The signed byte sequence is the existing -01 adapter's fixed order:
`step_id`, `action_id`, recursively ordered `params`, `success`, `ts_ms`, `seq`.
Public key and signature encoding follow that existing adapter. The public key
carried by a receipt is not by itself an authority grant.

`action_id` is `artifact.send` or `artifact.receive` for its file's role.
`params` contains exactly `profile`, `role`, `source_id`, `correlation_id`,
`artifact_sha256`, `artifact_bytes`, `policy_epoch`. Profile and role must
match this contract and the file; all claim members are signed. `success` is
a strict boolean, not an assumed true value. The claimed artifact is compared
both to actual package bytes and to the receiver's separately expected artifact.

## 4. Receiver-selected context

Context fields are exactly `schema`, `expected`, `evaluation_time_ms`,
`historical_policies`, `current_policy`, `key_status`, `observations`.
Schema is `ttrace.handoff-receiver-context/v1`. Context bytes are hashed into
the report; their truth and provenance are accepted externally by the receiver,
not authenticated by embedding them in the package.

`expected` contains exactly `correlation_id`, `artifact_sha256`,
`artifact_bytes`, `roles`, `window_start_ms`, `audit_cutoff_ms`,
`snapshots_final_at_cutoff`. Roles bind exactly `sender` and `receiver` to
distinct source identifiers. Window start <= cutoff <= evaluation time.
Finality is a strict boolean receiver assertion about the supplied snapshots,
not proof of global event capture.

`historical_policies` is an array of at most 16 separately accepted archives,
with unique epochs. Each has `epoch`, `valid_from_ms`, `valid_until_ms`, `roles`.
Each role binding has exactly `source_id`, `public_key`, `not_before_ms`,
`not_after_ms`. The two roles use distinct source IDs and keys. Policy and key
validity intervals are nonempty, lower-inclusive and upper-exclusive. The
profile's scope is these two artifact-handoff roles; it grants no other action.

`current_policy` is null (missing) or the same policy structure plus `as_of_ms`
and `next_update_ms`. If its epoch also exists in the archive, the policy body
must match exactly; one epoch cannot identify two different policies.
`key_status` is null or contains exactly `as_of_ms`,
`next_update_ms`, `events`. A status snapshot is fresh only when
as_of <= evaluation_time < next_update. Future or expired snapshots are not
silently treated as current. `events` has at most 32 entries, each with exact
`public_key`, `kind`, `effective_at_ms`. Kind is `revoked` or `compromised`;
effective time <= as_of. At most one event per key is admitted, so the receiver
must resolve inconsistent event histories before supplying this selected view.

`observations` has at most two entries, with exact `receipt_sha256` and
`observed_at_ms`, unique by digest. Observation time <= evaluation time. These
are receiver-accepted records of first possession of the exact original receipt
bytes, not the receipt signer's own clock. Missing observation is insufficient;
observation earlier than the receipt's claimed time is contradictory evidence.
The tool does not manufacture a public timestamp authority or validate the
receiver's external archive service. A locally controlled example states that
its time basis is synthetic and is not external corroboration.

## 5. Temporal decision table

Historical authority means authority **at the accepted observation time**, not
proof of permission at an independently established execution/signing instant.
The report must preserve that distinction. Current authority means that the
presented signer's key, source, role and signed policy epoch match the current
policy at evaluation time; it is not permission to execute a new action.

| Evidence/context | Historical authority | Current authority |
|---|---|---|
| Invalid signature | Not evaluable from this receipt | Not evaluable from this receipt |
| Missing matching historical epoch | Insufficient archive | Evaluate separately if current context exists |
| Missing observation | Insufficient trusted observation | Evaluate separately |
| Claimed receipt time after observation | Contradictory time evidence | Does not repair the contradiction |
| Missing/stale/future key-status view | Insufficient current key-status evidence | Insufficient key-status evidence |
| Key/policy valid at observation; no effective event | Authorized at observation under accepted context | Depends on current policy/key/time |
| Expired key/policy at observation | Not authorized at observation | Depends on current policy/key/time |
| Revocation effective at/before observation | Not authorized at observation | Not authorized at/after revocation |
| Compromise effective at/before observation | Indeterminate after compromise; not accepted as historical authority | Not authorized at/after compromise |
| Revocation/compromise after independently accepted observation | Prior authority remains assessable under that time evidence | Not authorized once event is effective |
| Current policy/key rotation | Historical archived result is preserved | Old epoch/key is not current authorization |
| Receipt observed after audit cutoff | Does not repair the earlier supplied snapshot | Evaluate current authority separately |

An absent, stale or incomplete archive/status is not a negative proof about
the actual world; it is missing evidence. Receiver-accepted status completeness
and trustworthy time remain named assumptions. Signature/hash survival does
not increase freshness or current permissions.

## 6. Authenticated projection and result

Only presented receipts with valid signatures, historical role/key bindings,
accepted observations and historical authority are projected into OpenPoC-03.
Projection uses signed step ID, source, correlation ID, artifact digest and
claimed `ts_ms`; observation comes from the separate context. `type=sense`
represents observation of the declaration and invents no transition/commit.
`thread_id` is its role's source identifier; `side` is its fixed package role.

A present receipt that cannot be authenticated for projection yields
insufficient authenticated projection, rather than being silently dropped and
called a missing receiver. A genuinely absent counterpart is distinguished
from a present unverified one. Known late/out-of-window receipts are excluded
by the existing cutoff rules. Equal declared digests are not proof of effects.

Cutoff clarification: an otherwise authenticated but excluded receipt keeps its
visible signature, claim and authority fields, but its claim mismatch cannot
establish `violated-expected-claim` at that earlier cutoff. This applies equally
to wrong digests, correlations and declared failure. Expected artifact/manifest
binding is still checked separately. Final snapshots with a missing in-scope
counterpart can violate the supplied-snapshot contract; nonfinal snapshots
remain insufficient. A receipt exactly at the inclusive cutoff remains in scope.

Results separately expose manifest integrity, expected artifact binding,
native signature validity, signed claim binding, trusted observation status,
historical authority, current authority, pairwise snapshot consistency and
global capture completeness. The last remains `unproven` in every case.

The bounded handoff conclusion is supported only if both expected claims and
the artifact match, both successes are true, historical authentication holds,
and the final supplied snapshots are consistent at cutoff. All other dimensions
remain visible, including current-policy denial despite historical support.
No unconditional assurance score or universal `verified=true` is supplied.

## 7. Gates and non-claims

The implementation must include an actual controlled file copy and separately
signed sender/receiver records, a portable saved package, machine/human reports,
clean installed verification, and a corpus covering every temporal row and
strict input boundary above. A second implementation must reproduce the entire
declared corpus without importing the first verifier. Malformed-input failures
are explicit typed error codes, not accidental success or a leaked traceback.

Externally operated testing, a new reviewer's measured setup time, and an actual
useful decision from an external participant are separate remaining roadmap
gates. Internal fixtures, process separation, passing CI and successful merges
must not be counted as those external outcomes.
