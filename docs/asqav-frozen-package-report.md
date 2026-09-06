# Frozen Asqav source-package verification

Result: **agree** for the selected three-vector corpus.

Source commit: `17c814f9e2e51f005faa707d44adec0316534da8`.
Receiver pin-file SHA-256: `98198d80a72aa16a109f101289f421859bf2f2f7cbcbcb84a0c44fea5118263d`.
Transport manifest SHA-256: `4b90637a2bb929ceb83c4391bba6e4882cfa71b49e91c86af29f27d049b837b3`.

15 original source files matched the receiver-selected pins, including LICENSE.
Three manifest outcomes (format/outcome/reason_code) and 12 lock records matched.
Narrative notes are preserved independently, not required to be equal. Upstream code was not executed.

| Vector | Comparison | Signed marker |
|---|---|---|
| `asqav-14-omitted-action-chain` | agree | none |
| `asqav-15-unsigned-gap` | agree | unsigned_gap(count=2) |
| `asqav-16-chain-emission-blocked` | agree | chain_emission_blocked |

## Decision boundary

This reproduces the selected fixture comparison only. The receiver must obtain and
accept the pin file independently of the package. Matching hashes alone do not
authenticate the publisher; bundled JWKS are fixture data, not a production trust root.
A signed declaration does not independently establish its stated external cause.
Capture completeness, current authorization, freshness, real-world effects, and an
external pilot are not proved. The original upstream LICENSE travels unchanged;
T-Trace's license does not replace it.
