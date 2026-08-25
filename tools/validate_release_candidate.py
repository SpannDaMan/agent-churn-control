#!/usr/bin/env python3
"""Validate the standalone Anti-Churn public release candidate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from PIL import Image


sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "agent-churn-control"
CORE = PLUGIN / "scripts" / "churn_control.py"
EXPECTED_SUBTITLE = "Stop duplicate agent work"
EXPECTED_LONG = "Use this before repeating an agent test, review, retry, tool call, or promotion check. Anti-Churn compares the proposed local action with accepted evidence, reuses matching results, permits changed work through typed invalidation, and shows what may be skipped versus what still must run. Do not use rate-limit percentage as stop authority; it gates only the duplicate action and never stops the task, publishes, or changes permissions."
EXPECTED_PROMPTS = [
    "Steer: Audit this long build for scope drift and duplicate work. Reuse valid evidence, keep us on task, and stop token burn.",
    "@Anti-Churn Before another full test cycle, show what must run, what is covered, and what would duplicate prior evidence.",
    "@Anti-Churn The candidate changed after review. Show what evidence is invalid, what remains valid, and what must be rerun.",
]

REQUIRED_FILES = (
    ".gitattributes", ".gitignore", "LICENSE", "README.md", "BRAND.md", "DESIGN.md",
    "design.tokens.json", "CHANGELOG.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md",
    "PRIVACY.md", "PROVENANCE.md", "PUBLICATION-GATE.md", "RELEASE-CHECKLIST.md",
    "SECURITY.md", "SUPPORT.md", "TERMS.md", "THREAT-MODEL.md",
    ".agents/plugins/marketplace.json", ".claude-plugin/marketplace.json", ".github/workflows/test.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml", ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/CODEX-INSTALL.md", "docs/CLAUDE-INSTALL.md", "docs/DECISIONS-AND-RECEIPTS.md", "docs/EVALUATION.md",
    "docs/OPENAI-PLUGIN-SUBMISSION.md", "submission/openai-plugin-submission.json",
    "tests/test_release_validator.py",
    "tools/build_package_manifest.py", "tools/render_store_assets.py", "tools/validate_release_candidate.py",
    "plugins/agent-churn-control/.codex-plugin/plugin.json",
    "plugins/agent-churn-control/.claude-plugin/plugin.json",
    "plugins/agent-churn-control/skills/agent-churn-control/SKILL.md",
    "plugins/agent-churn-control/skills/agent-churn-control/agents/openai.yaml",
    "plugins/agent-churn-control/scripts/churn_control.py",
    "plugins/agent-churn-control/tests/test_churn_control.py",
    "plugins/agent-churn-control/assets/core-policy.json",
    "plugins/agent-churn-control/assets/contract.schema.json",
    "plugins/agent-churn-control/assets/authority-map.json",
    "plugins/agent-churn-control/assets/package-manifest.json",
    "plugins/agent-churn-control/assets/sample-event.json",
    "plugins/agent-churn-control/assets/sample-receipt.json",
    "plugins/agent-churn-control/assets/sample-efficiency-measurement.json",
    "plugins/agent-churn-control/assets/Agent Churn Control Vector Master 230826.svg",
    "plugins/agent-churn-control/assets/Agent Churn Control Vector Dark 230826.svg",
    "plugins/agent-churn-control/assets/Agent Churn Control Transparent Raster Master 230826.png",
    "plugins/agent-churn-control/assets/Anti-Churn Silver Satin Master 240826.png",
    "plugins/agent-churn-control/assets/Silver Satin Background Master 240826.png",
    "plugins/agent-churn-control/assets/Logo Generation Manifest 230826.json",
    "plugins/agent-churn-control/assets/icon.png",
    "plugins/agent-churn-control/assets/logo.png",
    "plugins/agent-churn-control/assets/logo-dark.png",
    "plugins/agent-churn-control/assets/screenshot1.png",
    "plugins/agent-churn-control/fixtures/v1/corpus.ndjson",
    "evals/agent-churn-control-activation-golden.json",
)

TEXT_SUFFIXES = {".md", ".txt", ".json", ".jsonl", ".py", ".yml", ".yaml", ".svg"}
REVISION_TEXT_NAMES = {"LICENSE", ".gitattributes", ".gitignore"}
GENERATED_PARTS = {".git", ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv", "venv", "dist", "build"}
PRIVATE_MARKERS = (
    "c:" + "/users/", "c:" + "\\users\\", "agent smith" + " projects", "runtime/" + "astf",
    "local://" + "twscrape", "codex-running-task-churn-" + "plugin-hardening",
    "chatgpt.com/g/" + "g-p-", "private agent" + " smith task",
)
SECRET_PATTERNS = (
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_file_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES or path.name in REVISION_TEXT_NAMES:
        text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
        return text.encode("utf-8")
    return raw


def product_revision() -> str:
    entries: list[tuple[str, bytes]] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if not path.is_file() or any(part in GENERATED_PARTS for part in relative.parts) or relative.parts[0] == "validation":
            continue
        payload = canonical_file_bytes(path)
        entries.append((relative.as_posix(), payload))
    rows = [f"{relative}|{hashlib.sha256(payload).hexdigest()}|{len(payload)}" for relative, payload in sorted(entries, key=lambda item: item[0])]
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def validate_required_files() -> list[str]:
    return [f"required file missing: {relative}" for relative in REQUIRED_FILES if not (ROOT / relative).is_file()]


def validate_file_shape() -> list[str]:
    errors: list[str] = []
    git_root = ROOT / ".git"
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in GENERATED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            if git_root.exists() and path.is_file():
                tracked = subprocess.run(
                    ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", relative.as_posix()],
                    capture_output=True,
                    text=True,
                )
                if tracked.returncode == 0:
                    errors.append(f"tracked generated residue not allowed: {relative}")
            continue
        if path.is_symlink():
            errors.append(f"symlink not allowed: {relative}")
        if path.is_file() and path.stat().st_size > 2_000_000:
            errors.append(f"file exceeds 2000000 bytes: {relative}")
    return errors


def validate_text_safety() -> list[str]:
    errors: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in GENERATED_PARTS for part in relative.parts):
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8-sig", errors="ignore")
        except OSError:
            continue
        lower = text.lower()
        for marker in PRIVATE_MARKERS:
            if marker in lower:
                errors.append(f"private marker {marker!r}: {relative}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"secret-like value: {relative}")
        if ("[" + "todo") in lower:
            errors.append(f"TODO placeholder: {relative}")
    return errors


def validate_json() -> list[str]:
    errors: list[str] = []
    for path in ROOT.rglob("*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    return errors


def validate_metadata() -> list[str]:
    errors: list[str] = []
    manifest = load_json(PLUGIN / ".codex-plugin" / "plugin.json")
    submission = load_json(ROOT / "submission" / "openai-plugin-submission.json")
    marketplace = load_json(ROOT / ".agents" / "plugins" / "marketplace.json")
    claude_marketplace = load_json(ROOT / ".claude-plugin" / "marketplace.json")
    claude_plugin = load_json(PLUGIN / ".claude-plugin" / "plugin.json")
    policy = load_json(PLUGIN / "assets" / "core-policy.json")
    contract = load_json(PLUGIN / "assets" / "contract.schema.json")
    measurement = load_json(PLUGIN / "assets" / "sample-efficiency-measurement.json")
    skill_text = (PLUGIN / "skills" / "agent-churn-control" / "SKILL.md").read_text(encoding="utf-8-sig")
    expected = {
        "name": "agent-churn-control", "version": "0.1.3", "license": "MIT",
        "homepage": "https://github.com/SpannDaMan/agent-churn-control",
        "repository": "https://github.com/SpannDaMan/agent-churn-control",
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            errors.append(f"plugin.json {field} mismatch")
    if manifest.get("author", {}).get("name") != "Orbral":
        errors.append("plugin author must be Orbral")
    interface = manifest.get("interface", {})
    checks = {
        "displayName": "Anti-Churn", "shortDescription": EXPECTED_SUBTITLE,
        "longDescription": EXPECTED_LONG, "developerName": "Orbral", "category": "Developer Tools",
        "privacyPolicyURL": "https://github.com/SpannDaMan/agent-churn-control/blob/main/PRIVACY.md",
        "termsOfServiceURL": "https://github.com/SpannDaMan/agent-churn-control/blob/main/TERMS.md",
    }
    for field, value in checks.items():
        if interface.get(field) != value:
            errors.append(f"plugin interface {field} mismatch")
    if interface.get("defaultPrompt") != EXPECTED_PROMPTS:
        errors.append("plugin starter prompts drifted")
    if "screenshots" in interface:
        errors.append("skills-only plugin must not declare interface.screenshots")
    for field in ("composerIcon", "logo", "logoDark"):
        value = interface.get(field)
        if not isinstance(value, str) or not (PLUGIN / value).is_file():
            errors.append(f"plugin asset missing: {field}")
    if "screenshots" in interface:
        errors.append("skills-only plugin must not declare interface.screenshots")
    if submission.get("short_description") != EXPECTED_SUBTITLE or submission.get("long_description") != EXPECTED_LONG:
        errors.append("submission copy drifted")
    if submission.get("plugin_name") != "Anti-Churn":
        errors.append("submission plugin_name must be Anti-Churn")
    if submission.get("starter_prompts") != EXPECTED_PROMPTS:
        errors.append("submission prompts drifted")
    if submission.get("publisher") != "Orbral" or submission.get("submission_type") != "skills_only":
        errors.append("submission publisher or type mismatch")
    if len(submission.get("positive_tests", [])) != 5 or len(submission.get("negative_tests", [])) != 3:
        errors.append("submission must contain five positive and three negative tests")
    if '"<PLUGIN_ROOT>/scripts/churn_control.py"' not in skill_text or "never resolve plugin files from the user's project working directory" not in skill_text:
        errors.append("skill installed-root command routing is missing")
    metric_properties = contract.get("properties", {}).get("metrics", {}).get("items", {}).get("properties", {})
    if set(metric_properties.get("name", {}).get("enum", [])) != set(policy.get("allowed_metric_names", [])):
        errors.append("contract metric names drifted from runtime policy")
    if set(metric_properties.get("unit", {}).get("enum", [])) != set(policy.get("allowed_metric_units", [])):
        errors.append("contract metric units drifted from runtime policy")
    invalidation_properties = contract.get("$defs", {}).get("invalidation", {}).get("properties", {})
    if invalidation_properties.get("invalidates", {}).get("maxItems") != 1:
        errors.append("contract invalidation cardinality drifted from runtime")
    change_items = invalidation_properties.get("changes", {}).get("items", {})
    if set(change_items.get("required", [])) != {"field", "before", "after"} or change_items.get("additionalProperties") is not False:
        errors.append("contract invalidation change shape drifted from runtime")
    evidence_kind_enum = invalidation_properties.get("evidence", {}).get("items", {}).get("properties", {}).get("kind", {}).get("enum", [])
    if set(evidence_kind_enum) != set(policy.get("allowed_evidence_kinds", [])):
        errors.append("contract invalidation evidence kinds drifted from runtime policy")
    if measurement.get("measured_example", {}).get("basis_receipt_ids") != measurement.get("basis_receipt_ids"):
        errors.append("sample efficiency metric basis is not self-contained")
    if marketplace.get("name") != "agent-churn-control" or len(marketplace.get("plugins", [])) != 1:
        errors.append("marketplace root mismatch")
    else:
        entry = marketplace["plugins"][0]
        if entry.get("name") != "agent-churn-control" or entry.get("source", {}).get("path") != "./plugins/agent-churn-control":
            errors.append("marketplace plugin entry mismatch")
        if entry.get("policy") != {"installation":"AVAILABLE", "authentication":"ON_INSTALL"}:
            errors.append("marketplace policy mismatch")
    claude_entries = claude_marketplace.get("plugins", [])
    if claude_marketplace.get("name") != "agent-churn-control" or claude_marketplace.get("owner", {}).get("name") != "Orbral" or len(claude_entries) != 1:
        errors.append("Claude marketplace root mismatch")
    else:
        claude_entry = claude_entries[0]
        if claude_entry.get("name") != "anti-churn" or claude_entry.get("source") != "./plugins/agent-churn-control" or claude_entry.get("version") != "0.1.3":
            errors.append("Claude marketplace plugin entry mismatch")
    if claude_plugin.get("name") != "anti-churn" or claude_plugin.get("version") != "0.1.3" or claude_plugin.get("author", {}).get("name") != "Orbral":
        errors.append("Claude plugin identity mismatch")
    return errors


def validate_activation_suite() -> list[str]:
    errors: list[str] = []
    suite = load_json(ROOT / "evals" / "agent-churn-control-activation-golden.json")
    expected_fields = {"id", "class", "prompt", "expected_activation", "expected_behavior", "prohibited_behavior", "evidence_oracle"}
    cases = suite.get("cases", [])
    if suite.get("schema_version") != "1.0" or suite.get("plugin") != "agent-churn-control":
        errors.append("activation suite identity mismatch")
    if not isinstance(cases, list) or len(cases) != 30:
        return errors + ["activation suite must contain exactly 30 cases"]
    counts = {"direct": 0, "indirect": 0, "negative": 0}
    seen_ids: set[str] = set()
    seen_prompts: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != expected_fields:
            errors.append(f"activation case {index} fields mismatch")
            continue
        case_id = str(case.get("id", ""))
        case_class = str(case.get("class", ""))
        prompt = str(case.get("prompt", "")).casefold()
        if not case_id or case_id in seen_ids or not prompt or prompt in seen_prompts:
            errors.append(f"activation case {index} identity is missing or duplicated")
        seen_ids.add(case_id)
        seen_prompts.add(prompt)
        if case_class not in counts:
            errors.append(f"activation case {case_id} class is invalid")
            continue
        counts[case_class] += 1
        if case.get("expected_activation") is not (case_class in {"direct", "indirect"}):
            errors.append(f"activation case {case_id} expectation conflicts with class")
        for field in ("expected_behavior", "prohibited_behavior", "evidence_oracle"):
            if not isinstance(case.get(field), str) or not case[field].strip():
                errors.append(f"activation case {case_id} {field} is empty")
    if counts != {"direct": 10, "indirect": 10, "negative": 10}:
        errors.append(f"activation class counts mismatch: {counts}")
    return errors


def validate_assets() -> list[str]:
    errors: list[str] = []
    expected = {
        "icon.png": (512, 512, False), "logo.png": (1024, 1024, False),
        "logo-dark.png": (1024, 1024, False), "screenshot1.png": (1600, 1000, False),
    }
    for name, (width, height, transparent) in expected.items():
        path = PLUGIN / "assets" / name
        if not path.is_file():
            errors.append(f"asset missing: {name}")
            continue
        image = Image.open(path)
        if image.size != (width, height):
            errors.append(f"asset dimensions mismatch: {name} {image.size}")
        if transparent:
            if image.mode != "RGBA" or image.getchannel("A").getextrema() != (0, 255):
                errors.append(f"asset transparency invalid: {name}")
                continue
            box = image.getchannel("A").getbbox()
            if not box:
                errors.append(f"asset empty: {name}")
                continue
            width_fill = (box[2] - box[0]) / width
            height_fill = (box[3] - box[1]) / height
            if width_fill < 0.82 or height_fill < 0.70:
                errors.append(f"asset safe fill too small: {name} {width_fill:.3f}x{height_fill:.3f}")
        else:
            rgba = image.convert("RGBA")
            corners = (rgba.getpixel((0, 0))[3], rgba.getpixel((width - 1, 0))[3], rgba.getpixel((0, height - 1))[3], rgba.getpixel((width - 1, height - 1))[3])
            if corners != (255, 255, 255, 255):
                errors.append(f"asset must be opaque and full-bleed: {name}")
    return errors


def validate_runtime() -> list[str]:
    errors: list[str] = []
    self_test = subprocess.run([sys.executable, "-B", str(CORE), "self-test"], cwd=ROOT, capture_output=True, text=True)
    if self_test.returncode != 0:
        errors.append(f"self-test failed: {self_test.stderr.strip() or self_test.stdout.strip()}")
    package = subprocess.run([sys.executable, "-B", str(CORE), "verify-package"], cwd=ROOT, capture_output=True, text=True)
    if package.returncode != 0:
        errors.append(f"package verification failed: {package.stderr.strip() or package.stdout.strip()}")
    sample = subprocess.run([sys.executable, "-B", str(CORE), "verify", "--receipt", str(PLUGIN / "assets" / "sample-receipt.json")], cwd=ROOT, capture_output=True, text=True)
    if sample.returncode != 0:
        errors.append(f"sample receipt verification failed: {sample.stderr.strip() or sample.stdout.strip()}")
    return errors


def run_validation() -> dict[str, Any]:
    checks = {
        "required_files": validate_required_files(),
        "file_shape": validate_file_shape(),
        "text_safety": validate_text_safety(),
        "json": validate_json(),
        "metadata": validate_metadata(),
        "assets": validate_assets(),
        "activation_suite": validate_activation_suite(),
        "runtime": validate_runtime(),
    }
    errors = sorted({error for group in checks.values() for error in group})
    return {
        "status": "pass" if not errors else "fail",
        "candidate": "agent-churn-control 0.1.3",
        "product_revision_sha256": product_revision(),
        "checks": {name: "pass" if not group else "fail" for name, group in checks.items()},
        "errors": errors,
    }


def main() -> int:
    result = run_validation()
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
