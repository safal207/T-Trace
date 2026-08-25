"""Canonical JSON and digest helpers for T-Trace portable causality profiles."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the T-Trace canonical subset."""


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating_point_values_are_not_canonical")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("canonical_object_keys_must_be_strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    if hasattr(value, "to_dict"):
        return _normalize(value.to_dict())
    raise CanonicalizationError(f"unsupported_canonical_type:{type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize using the strict, deterministic JSON subset used by this profile."""

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_object(value: Any) -> str:
    return sha256_hex(canonical_json_bytes(value))


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def require_sha256(value: object, field: str) -> str:
    if not is_sha256(value):
        raise ValueError(f"invalid_sha256:{field}")
    return str(value)
