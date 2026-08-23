from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools" / "validate_release_candidate.py"
SPEC = importlib.util.spec_from_file_location("release_validator", PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def test_release_candidate_passes() -> None:
    result = validator.run_validation()
    assert result["status"] == "pass", result["errors"]


def test_public_copy_is_exactly_benchmarked() -> None:
    assert validator.validate_metadata() == []


def test_store_assets_have_expected_shape() -> None:
    assert validator.validate_assets() == []


def test_public_tree_contains_no_private_markers() -> None:
    assert validator.validate_text_safety() == []


def test_product_revision_normalizes_text_line_endings(tmp_path: Path) -> None:
    lf = tmp_path / "lf.md"
    crlf = tmp_path / "crlf.md"
    lf.write_bytes(b"one\ntwo\n")
    crlf.write_bytes(b"one\r\ntwo\r\n")
    assert validator.canonical_file_bytes(lf) == validator.canonical_file_bytes(crlf)
