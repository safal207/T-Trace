# Frozen source package: selected Asqav inputs

This is the acquisition and offline transport layer for the existing
[Asqav capture comparison](asqav-capture-compatibility.md). It retains one
receipt verifier, `openpoc.asqav_capture_compat`, while preserving the useful
source-binding and frozen-input work identified in [PR #37](https://github.com/safal207/T-Trace/pull/37).
It is not a general-purpose evidence archive or the planned artifact-handoff pilot.

## Recipient and decision

The recipient is a conformance reviewer who has independently accepted the
[source-selection pins](../profiles/asqav-source-selection-v1.json) from a chosen
T-Trace revision. The bounded decision is: do these exact selected source files
reproduce the three-vector comparison, under those accepted pins?

There are three separate checks:

1. Receiver-selected pins bind the source revision, 15 original files, byte
   counts, SHA-256, and Git blob identifiers. They must be obtained and reviewed
   independently of the package. The repository's example pin file is an
   explicit input, not an automatically trusted root.
2. Transport checking matches every original file against those pins, then
   checks three manifest outcome records and 12 lock records.
3. The existing receipt implementation independently verifies the signatures,
   predecessor links, and signed markers in those same acquired bytes.

A package that matches hashes but fails a receipt signature is not an agreed
comparison. A package's own manifest and JWKS do not assign production authority
to its publisher or signer. Physical separation of the pin file is enforced,
but filesystem location alone cannot prove independent provenance.

## Exact transport contract

- Selection schema: `ttrace.asqav-source-selection/v1`.
- Package schema: `ttrace.asqav-frozen-package/v1`.
- Report schema: `ttrace.asqav-frozen-package-report/v1`.
- Upstream subject: `jagmarques/asqav-sdk`, commit
  `17c814f9e2e51f005faa707d44adec0316534da8`.
- Three vectors: 14, 15, 16. All 12 original vector paths are preserved, including
  the three originally separate JWKS paths. Two upstream manifests and the
  original root `LICENSE` bring the count to 15 files / 88,493 source bytes.
- One generated root `manifest.json` describes the selection. It is deterministic
  transport metadata, not a new signed envelope. Verification requires its
  exact bytes to match the manifest derived from the receiver's pins.
- Original files are copied as bytes. JSON formatting, signatures, declared
  notes, paths, and licensing text are not rewritten or deduplicated.
- Unknown paths/files/fields/versions, duplicate JSON keys, malformed scalar
  types, missing files, nonregular files, links, and altered bytes fail closed.
  Metadata is bounded to 128 KiB; each selected source file to 1 MiB; inventory
  to 64 entries. No archive extraction is performed.

The pinned upstream's `notes` text differs between `manifest.json` and each
`expected.json`. Both originals are bound in full by their file pins. Only
`format`, `outcome`, and `reason_code` are required to agree between records;
this is stated explicitly in the report. Requiring full narrative equality,
as the old alternative did, rejects the actual pinned corpus. Tests therefore
include differing notes, rather than manufacturing identical narratives.

## Acquire once

Acquire the upstream repository and independently review/accept the selected
T-Trace pin file. Acquisition may require network access. Do not execute the
upstream verifier or install the upstream project.

With the pinned commit available in your local Git object database:

```bash
python -m openpoc.asqav_frozen_package export /path/to/asqav-sdk /path/to/new-package \
  --trusted-pins /separate/reviewer/asqav-source-selection-v1.json
```

The exporter reads the explicitly selected Git commit's objects, with Git
replacement objects disabled, not mutable working-tree files. It checks object
size and hashes before writing, validates the source relationships, and refuses
an existing output path. It does not verify publisher signatures on the Git
commit; the accepted pins remain the receiver's trust origin. A storage error
may leave an incomplete destination; a later export will not overwrite it.

Use controlled local storage during acquisition/verification. Concurrent hostile
filesystem mutation is not an isolation boundary supplied by this tool.

## Verify later, offline

After installing T-Trace and the `receipts` dependency extra, the recipient needs
only the package and the separately accepted pin file. Git, the upstream checkout,
the producer service, and network calls are not used by this operation:

```bash
python -m openpoc.asqav_frozen_package verify /path/to/package \
  --trusted-pins /separate/reviewer/asqav-source-selection-v1.json
python -m openpoc.asqav_frozen_package verify /path/to/package \
  --trusted-pins /separate/reviewer/asqav-source-selection-v1.json --format markdown
```

The verifier checks and holds the pinned file bytes, then passes parsed documents
from those bytes directly to the existing receipt implementation; it does not
reopen source files between source-binding and signature checking.

The [machine report](asqav-frozen-package-report.json) and
[human report](asqav-frozen-package-report.md) are regenerated from the exact
upstream objects in the existing pinned CI workflow. The original comparison
report and regression suite remain active. A new synthetic corpus covers local
drift, self-pinning, strict types, metadata bounds, differing notes, duplicate
source records, dirty checkouts, and receipt failure despite accepted byte pins.
The local Windows environment may lack permission to create symlinks; the same
symlink rejection test also runs on Linux CI.

## Local validation record (2026-09-06)

The full local suite passed 439 tests, with one Windows symlink-creation
permission skip. A fresh Windows Python 3.12.14 environment installed the
non-editable T-Trace wheel and previously acquired dependencies using
`--no-index --no-cache-dir`. Dependencies were cryptography 46.0.4, cffi 2.1.1,
and pycparser 3.0. The wheel's SHA-256 was
`aeb414787ee1aca3383dbbc7357614b4f20ab48823db038a5be0588d88afc5db`.
From outside the checkout, `python -I` loaded both verifier modules and
cryptography only from that fresh environment; the JSON report matched the
committed report after platform newline normalization. This is an internally
operated installation check, not an external pilot or proof for all platforms.

## License and disclosure boundary

At the selected revision, the upstream root `LICENSE` says Elastic License 2.0
and contains the Asqav copyright notice. The exporter includes that exact file
with the original selected data. It does not copy upstream verifier code into
the T-Trace library, remove notices, or replace the upstream license with MIT.
Recipients must review the included terms for their own intended use.

This package contains public synthetic conformance receipts, fixture keys,
expected outcomes, source manifests, and licensing text. It must not be used as
a template for silently distributing private production traces, credentials,
or identity-bearing receipts. A real exchange needs its own disclosure review.

No claims are made about global capture completeness, real-world outage causes,
production non-bypassability, policy evaluation of unsigned actions, current
authorization, freshness, publisher endorsement, or an external human pilot.
This preserves and bounds an existing interoperability result; it is not the
roadmap's final release or evidence of adoption.
