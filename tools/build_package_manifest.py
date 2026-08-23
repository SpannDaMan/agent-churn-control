#!/usr/bin/env python3
"""Rebuild the Agent Churn Control package manifest deterministically."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "agent-churn-control"
MANIFEST = PLUGIN / "assets" / "package-manifest.json"
TEXT_SUFFIXES = {".json", ".jsonl", ".ndjson", ".md", ".py", ".yaml", ".yml", ".svg"}
GENERATED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv", "dist", "build"}


def canonical_file_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES:
        return raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return raw


def main() -> int:
    files: list[Path] = []
    for path in PLUGIN.rglob("*"):
        relative = path.relative_to(PLUGIN)
        if any(part in GENERATED_PARTS for part in relative.parts):
            raise SystemExit(f"generated residue must be removed before packaging: {relative.as_posix()}")
        if path.is_symlink():
            raise SystemExit(f"symlink is not packageable: {relative.as_posix()}")
        if path.is_file() and path.resolve() != MANIFEST.resolve():
            files.append(path)

    rows: list[dict[str, object]] = []
    aggregate_rows: list[str] = []
    for path in sorted(files, key=lambda item: item.relative_to(PLUGIN).as_posix()):
        relative = path.relative_to(PLUGIN).as_posix()
        payload = canonical_file_bytes(path)
        sha256 = hashlib.sha256(payload).hexdigest()
        rows.append({"path": relative, "sha256": sha256, "bytes": len(payload)})
        aggregate_rows.append(f"{relative}|{sha256}|{len(payload)}")

    aggregate = hashlib.sha256("\n".join(aggregate_rows).encode("utf-8")).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "plugin_id": "agent-churn-control",
        "version": "0.1.0",
        "release_state": "public_release_candidate",
        "aggregate_algorithm": "sha256_sorted_path_canonical_hash_bytes_v2",
        "package_payload_sha256": aggregate,
        "files": rows,
        "authority_map_path": "assets/authority-map.json",
        "fixture_corpus_version": "1",
        "validator_version": "0.1.0",
        "publication_or_installation_authorized": True,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": "pass", "file_count": len(rows), "package_payload_sha256": aggregate}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
