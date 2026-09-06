# Installed verifier portability

The base validator lives in `ttrace.validation`. OpenPoC imports that packaged
module rather than loading `scripts/validate_ttrace.py` from a source checkout.
The old script remains a compatibility wrapper around the same functions;
the move does not change base v0.1 validation semantics.

## Install and run

Build a wheel from the chosen checkout, recording its commit and environment:

```bash
python -m pip wheel --no-deps --wheel-dir dist .
```

Install that wheel into an isolated environment. The core verifier commands
do not require third-party runtime dependencies:

```bash
python -m pip install --no-index --no-deps dist/t_trace-0.1.0-py3-none-any.whl
ttrace-validate /path/to/trace.jsonl
ttrace-assurance /path/to/openpoc-01/scenario.json
ttrace-reproducibility /path/to/openpoc-02/scenario.json
ttrace-cross-source /path/to/openpoc-03/scenario.json
```

Replace the input paths with your actual files. Console commands require the
environment's scripts directory on PATH, usually by activating the environment.
Equivalent commands using that environment's Python are:

```bash
python -m ttrace.validation /path/to/trace.jsonl
python -m openpoc.verify_assurance /path/to/openpoc-01/scenario.json
python -m openpoc.verify_reproducibility /path/to/openpoc-02/scenario.json
python -m openpoc.verify_cross_source /path/to/openpoc-03/scenario.json
```

Scenario manifests and their referenced inputs must travel together. The
wheel contains verifier code, not the examples corpus or an authenticated
evidence package. Receipt-compatibility verifiers additionally need the
`receipts` extra (`cryptography`); installing dependencies is a separate
acquisition step from an offline core-verifier run.

## Executable packaging gate

```bash
python scripts/verify_installed_verifiers.py dist/t_trace-0.1.0-py3-none-any.whl
```

The gate creates a fresh temporary environment, installs only the supplied
wheel with `--no-index --no-deps`, and copies fixture inputs outside the source
checkout. It removes inherited Python path overrides, verifies imported module
locations, runs seven isolated module commands (`python -I`), and exercises
all four installed console entry points. It checks actual JSON verdict fields,
including violated and insufficient outcomes, not just successful exit codes.
Temporary environment and fixture copies are removed on completion.

The report binds the wheel by SHA-256 and names its runtime. Building the
wheel may require network access for build dependencies; the subsequent
installation gate uses only the local wheel. CI runs the same gate on Linux.

This is an installation/packaging check, not an independently operated review,
an authenticated portable proof, a freshness mechanism, or a production
capture-completeness claim. See the [reviewer path](reviewer-path.md) for
interpreting the fixture results.
