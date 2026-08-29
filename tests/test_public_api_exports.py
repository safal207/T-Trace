from __future__ import annotations

import ttrace


def test_public_all_contains_unique_string_names() -> None:
    assert all(isinstance(name, str) for name in ttrace.__all__)
    assert len(ttrace.__all__) == len(set(ttrace.__all__))


def test_star_import_exports_every_declared_public_name() -> None:
    namespace: dict[str, object] = {}
    exec("from ttrace import *", namespace)

    for name in ttrace.__all__:
        assert name in namespace
