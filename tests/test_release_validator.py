from __future__ import annotations

import importlib.util
import hashlib
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


def test_activation_suite_has_ten_direct_ten_indirect_and_ten_negative_cases() -> None:
    assert validator.validate_activation_suite() == []


def test_claude_provider_package_is_present_and_consistent() -> None:
    assert validator.validate_metadata() == []


def test_public_tree_contains_no_private_markers() -> None:
    assert validator.validate_text_safety() == []


def test_private_markers_are_scanned_in_nonstandard_text_files(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".env").write_text("SOURCE=c:" + "/users/private/operator\n", encoding="utf-8")
    monkeypatch.setattr(validator, "ROOT", tmp_path)
    assert any("private marker" in item for item in validator.validate_text_safety())


def test_product_revision_normalizes_text_line_endings(tmp_path: Path) -> None:
    lf = tmp_path / "lf.md"
    crlf = tmp_path / "crlf.md"
    lf.write_bytes(b"one\ntwo\n")
    crlf.write_bytes(b"one\r\ntwo\r\n")
    assert validator.canonical_file_bytes(lf) == validator.canonical_file_bytes(crlf)


def test_product_revision_normalizes_required_dotfiles(tmp_path: Path) -> None:
    lf = tmp_path / ".gitignore"
    crlf = tmp_path / ".gitattributes"
    lf.write_bytes(b"one\ntwo\n")
    crlf.write_bytes(b"one\r\ntwo\r\n")
    assert validator.canonical_file_bytes(lf) == validator.canonical_file_bytes(crlf)


def test_product_revision_sorts_canonical_posix_paths(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "z").mkdir()
    (tmp_path / "a").mkdir()
    (tmp_path / "z" / "two.md").write_bytes(b"two\r\n")
    (tmp_path / "a" / "one.md").write_bytes(b"one\n")
    monkeypatch.setattr(validator, "ROOT", tmp_path)
    rows = []
    for relative in ("a/one.md", "z/two.md"):
        payload = validator.canonical_file_bytes(tmp_path / Path(relative))
        rows.append(f"{relative}|{hashlib.sha256(payload).hexdigest()}|{len(payload)}")
    expected = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
    assert validator.product_revision() == expected
