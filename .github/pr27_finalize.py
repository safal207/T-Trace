from __future__ import annotations

import re
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"expected text missing in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "ttrace/lineage_membership.py",
    "    sibling_hash_count: Optional[int] = None\n",
    "    selected_sibling_hash_count: Optional[int] = None\n"
    "    current_sibling_hash_count: Optional[int] = None\n"
    "    sibling_hash_count: Optional[int] = None\n",
)
replace_once(
    "ttrace/lineage_membership.py",
    '            sibling_hash_count=len(proof["sibling_path"]),\n',
    '            selected_sibling_hash_count=len(proof["sibling_path"]),\n'
    "            current_sibling_hash_count=len(\n"
    '                proof["current_cycle_sibling_path"]\n'
    "            ),\n"
    "            sibling_hash_count=(\n"
    '                len(proof["sibling_path"])\n'
    '                + len(proof["current_cycle_sibling_path"])\n'
    "            ),\n",
)
replace_once(
    "ttrace/lineage_membership.py",
    "    except (KeyError, RecursionError, TypeError, ValueError) as error:\n"
    "        return LineageMembershipDecision(False, str(error))\n",
    "    except RecursionError:\n"
    "        return LineageMembershipDecision(\n"
    '            False, "selective_disclosure_too_deep"\n'
    "        )\n"
    "    except (KeyError, TypeError, ValueError) as error:\n"
    "        return LineageMembershipDecision(False, str(error))\n",
)

replace_once(
    "tests/test_lineage_membership.py",
    "from copy import deepcopy\nimport sys\n",
    "import sys\nfrom copy import deepcopy\n",
)
replace_once(
    "tests/test_lineage_membership.py",
    "def _history(count: int = 5):\n",
    "def _history(\n"
    '    count: int = 5, *, initial_state_label: str = "epoch-0"\n'
    "):\n",
)
replace_once(
    "tests/test_lineage_membership.py",
    '        semantic_state_sha256=_sha("epoch-0"),\n',
    "        semantic_state_sha256=_sha(initial_state_label),\n",
)
replace_once(
    "tests/test_lineage_membership.py",
    "    assert decision.disclosed_cycle_index == 3\n"
    "    assert decision.sibling_hash_count == 3\n",
    "    assert decision.disclosed_cycle_index == 3\n"
    "    assert decision.selected_sibling_hash_count == 3\n"
    "    assert decision.current_sibling_hash_count == 3\n"
    "    assert decision.sibling_hash_count == 6\n",
)
replace_once(
    "tests/test_lineage_membership.py",
    "    decision = verify_selective_lineage_disclosure(disclosure)\n"
    "    assert decision.verified is False\n\n\n"
    "def test_disclosed_accumulator_must_bind_selected_cycle() -> None:\n",
    "    decision = verify_selective_lineage_disclosure(disclosure)\n"
    "    assert decision.verified is False\n"
    '    assert decision.reason == "selective_disclosure_too_deep"\n\n\n'
    "def test_disclosed_accumulator_must_bind_selected_cycle() -> None:\n",
)
replace_once(
    "tests/test_lineage_membership.py",
    "def test_builder_rejects_a_non_tip_accumulator() -> None:\n"
    "    records, accumulator = _history(5)\n"
    '    old_accumulator = records[-2]["lineage_accumulator"]\n'
    '    with pytest.raises(ValueError, match="cycle_count_accumulator_mismatch"):\n'
    "        build_lineage_membership_anchor(\n"
    "            records,\n"
    "            old_accumulator,\n"
    "            membership_contract_sha256=MEMBERSHIP_CONTRACT,\n"
    "            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,\n"
    "        )\n"
    "    assert accumulator != old_accumulator\n",
    "def test_builder_rejects_a_non_tip_accumulator() -> None:\n"
    "    records, accumulator = _history(5)\n"
    "    _, alternate_accumulator = _history(\n"
    '        5, initial_state_label="alternate-epoch-0"\n'
    "    )\n"
    "    assert accumulator != alternate_accumulator\n"
    "    assert (\n"
    '        accumulator["completed_reconciliation_cycles"]\n'
    '        == alternate_accumulator["completed_reconciliation_cycles"]\n'
    "    )\n"
    '    with pytest.raises(ValueError, match="current_accumulator_not_chain_tip"):\n'
    "        build_lineage_membership_anchor(\n"
    "            records,\n"
    "            alternate_accumulator,\n"
    "            membership_contract_sha256=MEMBERSHIP_CONTRACT,\n"
    "            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,\n"
    "        )\n\n\n"
    "def test_builder_rejects_accumulator_with_wrong_cycle_count() -> None:\n"
    "    records, accumulator = _history(5)\n"
    '    old_accumulator = records[-2]["lineage_accumulator"]\n'
    '    with pytest.raises(ValueError, match="cycle_count_accumulator_mismatch"):\n'
    "        build_lineage_membership_anchor(\n"
    "            records,\n"
    "            old_accumulator,\n"
    "            membership_contract_sha256=MEMBERSHIP_CONTRACT,\n"
    "            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,\n"
    "        )\n"
    "    assert accumulator != old_accumulator\n",
)

replace_once(
    "scripts/verify_lineage_membership.py",
    '        "sibling_hash_count": decision.sibling_hash_count,\n',
    '        "selected_sibling_hash_count": (\n'
    "            decision.selected_sibling_hash_count\n"
    "        ),\n"
    '        "current_sibling_hash_count": decision.current_sibling_hash_count,\n'
    '        "sibling_hash_count": decision.sibling_hash_count,\n',
)

replace_once(
    "spec/lineage-membership-profile-v0.1.md",
    "selected cycle + O(log n) sibling hashes\n",
    "selected cycle + two O(log n) sibling paths\n",
)
replace_once(
    "spec/lineage-membership-profile-v0.1.md",
    "hashes.\n\nThe verifier learns:\n",
    "hashes. The reference disclosure carries two independently checked paths:\n\n"
    "- one for the selected historical cycle;\n"
    "- one for the current/final cycle that binds the root to the supplied tip.\n\n"
    "Therefore the transmitted proof material is still `O(log n)`, with explicit\n"
    "counts reported as `selected_sibling_hash_count`,\n"
    "`current_sibling_hash_count`, and their total `sibling_hash_count`.\n\n"
    "The verifier learns:\n",
)

init_path = Path("ttrace/__init__.py")
init_text = init_path.read_text(encoding="utf-8")
start = init_text.index("__all__ = [")
end = init_text.index("]\n", start) + 2
block = init_text[start:end]
entries = re.findall(r'    "([^"]+)",', block)
if not entries:
    raise RuntimeError("__all__ entries missing")
if len(entries) != len(set(entries)):
    raise RuntimeError("duplicate __all__ entries")
sorted_block = "__all__ = [\n"
for entry in sorted(entries):
    sorted_block += f'    "{entry}",\n'
sorted_block += "]\n"
init_path.write_text(
    init_text[:start] + sorted_block + init_text[end:],
    encoding="utf-8",
)
