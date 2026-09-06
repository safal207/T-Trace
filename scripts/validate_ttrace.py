"""Source-checkout compatibility entry point for the packaged base validator."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.validation import (
    ALLOWED_TYPES,
    REQUIRED_FIELDS,
    main,
    parse_ts,
    read_jsonl,
    validate_file,
    validate_records,
)


if __name__ == "__main__":
    raise SystemExit(main())
