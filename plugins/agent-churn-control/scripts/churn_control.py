#!/usr/bin/env python3
"""Backend-free duplicate-work and evidence-reuse decision core."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "assets" / "core-policy.json"
CORPUS_PATH = ROOT / "fixtures" / "v1" / "corpus.ndjson"
DIGEST_FIELDS = [
    "action_scope_digest", "requirements_digest", "candidate_digest",
    "dependency_digest", "policy_digest", "evaluator_digest", "environment_digest",
]
WORK_KEY_FIELDS = [
    "schema_version", "action_kind", "action_scope_digest", "requirements_digest",
    "candidate_digest", "dependency_digest", "policy_digest", "evaluator_digest",
    "environment_digest", "environment_independent",
]
PROHIBITED_RECEIPT_KEYS = {
    "prompt", "output", "content", "command", "test_log", "file_content", "secret",
    "token", "credential", "absolute_path", "source_text", "participant_identity",
}
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
ACTION_KINDS = {"targeted_test", "broad_test", "premium_review", "retry", "tool_call", "panel", "plan_revision", "artifact", "promotion"}
MATERIAL_PROGRESS_STATES = {"yes", "no", "unknown"}
METRIC_STATUSES = {"measured", "derived", "unknown", "stale"}
INTERVENTION_LEVELS = {"bypass", "observe", "enforce", "promotion_gate"}
DECISIONS = {"allow", "allow_with_advisory", "allow_reexecution", "reuse_prior_evidence", "local_fix_required", "block_this_local_action", "promotion_ready", "promotion_not_ready"}
OUTCOMES = {"pass", "reused", "blocked", "not_ready", "local_failure"}
REASON_CODES = {
    "first_equivalent_action", "rate_advisory_only", "work_identity_incomplete",
    "typed_invalidation_consumed", "equivalent_passing_evidence_exists",
    "deterministic_local_failure", "fanout_invalid", "promotion_evidence_complete",
    "promotion_evidence_incomplete", "invalidation_already_consumed",
    "typed invalidation is required", "invalidation reason_code is not allowed",
    "invalidation_id does not match canonical fingerprint",
    "invalidation does not identify the prior receipt",
    "invalidation action scope does not match prior receipt",
    "invalidation changes contain an invalid field or unchanged value",
    "invalidation evidence is invalid", "prior_evidence_corrupt requires verifier_report_digest",
}
RECEIPT_FIELDS = [
    "schema_version", "receipt_id", "event_id", "task_id", "attempt_id", "model_ref",
    "policy_digest", "candidate_digest", "dependency_digest", "action_key", "work_key",
    "intervention_level", "decision", "reason_code", "outcome", "evidence_digest",
    "invalidation_id", "consumed_invalidation_ids", "fanout", "material_progress",
    "rate_advisories", "metrics", "validator_version", "fixture_corpus_version",
]


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return read_json(path)


def valid_digest(value: Any, *, nullable: bool = False) -> bool:
    if value is None:
        return nullable
    text = str(value)
    return text.startswith("sha256:") and len(text) == 71 and all(ch in "0123456789abcdef" for ch in text[7:])


def valid_opaque_id(value: Any, *, nullable: bool = False) -> bool:
    if value is None:
        return nullable
    return bool(OPAQUE_ID_RE.fullmatch(str(value)))


def validate_event(event: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = ["schema_version", "event_id", "task_id", "attempt_id", "action_kind", "action_scope_digest", "requirements_digest", "policy_digest", "evaluator_digest"]
    for field in required:
        if event.get(field) in (None, ""):
            errors.append(f"missing event field: {field}")
    if event.get("schema_version") != "1.0":
        errors.append("event schema_version must be 1.0")
    for field in ("event_id", "task_id", "attempt_id"):
        if not valid_opaque_id(event.get(field)):
            errors.append(f"{field} must be an opaque 1-128 character identifier")
    if not valid_opaque_id(event.get("model_ref"), nullable=True):
        errors.append("model_ref must be null or an opaque provider:model@revision identifier")
    if event.get("action_kind") not in ACTION_KINDS:
        errors.append("action_kind is invalid")
    for field in DIGEST_FIELDS:
        if field in event and not valid_digest(event.get(field), nullable=field in {"candidate_digest", "dependency_digest", "environment_digest"}):
            errors.append(f"invalid digest field: {field}")
    if event.get("environment_digest") is not None and event.get("environment_independent") is True:
        errors.append("environment_digest and environment_independent are mutually exclusive")
    if "environment_independent" in event and event.get("environment_independent") is not True:
        errors.append("environment_independent must be true when supplied")
    rate = event.get("rate_telemetry")
    if rate is not None:
        if not isinstance(rate, dict) or rate.get("state") not in policy["rate_states"]:
            errors.append("rate_telemetry.state is invalid")
        elif rate.get("effect") != "advisory":
            errors.append("rate_telemetry.effect must be advisory")
    progress = event.get("material_progress", {"status": "unknown", "evidence_digest": None})
    if not isinstance(progress, dict) or set(progress) - {"status", "evidence_digest"}:
        errors.append("material_progress must contain only status and evidence_digest")
    elif progress.get("status") not in MATERIAL_PROGRESS_STATES or not valid_digest(progress.get("evidence_digest"), nullable=True):
        errors.append("material_progress is invalid")
    metrics = event.get("metrics", [])
    if not isinstance(metrics, list):
        errors.append("metrics must be a list")
    else:
        for index, metric in enumerate(metrics):
            if not isinstance(metric, dict) or set(metric) - {"name", "status", "value", "unit", "source_ref", "basis_receipt_ids"}:
                errors.append(f"metrics[{index}] contains unsupported fields")
                continue
            if metric.get("name") not in policy["allowed_metric_names"]:
                errors.append(f"metrics[{index}] name is invalid")
            if metric.get("unit") not in policy["allowed_metric_units"]:
                errors.append(f"metrics[{index}] unit is invalid")
            if metric.get("status") not in METRIC_STATUSES:
                errors.append(f"metrics[{index}] has invalid status")
                continue
            if metric.get("status") in {"unknown", "stale"} and metric.get("value") is not None:
                errors.append(f"metrics[{index}] unknown/stale value must be null")
            if metric.get("status") in {"measured", "derived"} and (
                isinstance(metric.get("value"), bool)
                or not isinstance(metric.get("value"), (int, float))
                or not math.isfinite(float(metric.get("value")))
            ):
                errors.append(f"metrics[{index}] measured/derived value must be finite numeric")
            if metric.get("status") == "derived" and not metric.get("basis_receipt_ids"):
                errors.append(f"metrics[{index}] derived metric requires basis_receipt_ids")
            if not valid_opaque_id(metric.get("source_ref"), nullable=True):
                errors.append(f"metrics[{index}] source_ref must be null or an opaque identifier")
            if any(token in str(metric.get("name", "")) for token in ("saved", "avoided", "cost_of_pass")) and metric.get("status") in {"measured", "derived"} and not metric.get("basis_receipt_ids"):
                errors.append(f"metrics[{index}] numeric savings requires basis_receipt_ids")
            basis = metric.get("basis_receipt_ids", [])
            if not isinstance(basis, list) or any(not valid_digest(item) for item in basis):
                errors.append(f"metrics[{index}] basis_receipt_ids must be sha256 digests")
    return errors


def work_key(event: dict[str, Any]) -> str | None:
    value = {field: event.get(field) for field in WORK_KEY_FIELDS}
    required = ("schema_version", "action_kind", "action_scope_digest", "requirements_digest", "policy_digest", "evaluator_digest")
    if any(not value.get(field) for field in required):
        return None
    if not value.get("environment_digest") and value.get("environment_independent") is not True:
        return None
    return digest(value)


def action_key(event: dict[str, Any]) -> str:
    return digest({"action_kind": event.get("action_kind"), "action_scope_digest": event.get("action_scope_digest")})


def validate_fanout(fanout: Any) -> list[str]:
    if fanout is None:
        return []
    if not isinstance(fanout, dict):
        return ["fanout must be an object or omitted"]
    if fanout.get("declared") is not True:
        return ["fanout object is allowed only when declared is true"]
    required = ["packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "write_contract", "assignments", "runtime_receipt_ref"]
    errors = [f"fanout missing field: {field}" for field in required if fanout.get(field) in (None, "", [])]
    for field in ("packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "runtime_receipt_ref"):
        if fanout.get(field) and not valid_opaque_id(fanout.get(field)):
            errors.append(f"fanout {field} must be an opaque identifier")
    assignments = fanout.get("assignments", [])
    scopes: list[str] = []
    if isinstance(assignments, list):
        for row in assignments:
            if not isinstance(row, dict) or not row.get("agent_id") or not isinstance(row.get("write_scopes"), list):
                errors.append("fanout assignment requires agent_id and write_scopes")
                continue
            scopes.extend(str(item) for item in row["write_scopes"])
    if len(scopes) != len(set(scopes)):
        errors.append("fanout write scopes must be disjoint")
    return errors


def invalidation_fingerprint(record: dict[str, Any]) -> str:
    payload = {
        "schema_version": record.get("schema_version"),
        "invalidates": sorted(set(record.get("invalidates", []))),
        "action_scope_digest": record.get("action_scope_digest"),
        "reason_code": record.get("reason_code"),
        "changes": sorted(record.get("changes", []), key=canonical),
        "evidence": sorted(record.get("evidence", []), key=canonical),
    }
    return digest(payload)


def validate_invalidation(record: Any, prior: dict[str, Any], consumed: set[str], policy: dict[str, Any]) -> list[str]:
    if not isinstance(record, dict):
        return ["typed invalidation is required"]
    errors: list[str] = []
    for field in ("schema_version", "invalidation_id", "invalidates", "action_scope_digest", "reason_code", "changes", "evidence"):
        if record.get(field) in (None, "", []):
            errors.append(f"invalidation missing field: {field}")
    if record.get("reason_code") not in policy["allowed_invalidation_reasons"]:
        errors.append("invalidation reason_code is not allowed")
    if record.get("invalidation_id") != invalidation_fingerprint(record):
        errors.append("invalidation_id does not match canonical fingerprint")
    if record.get("invalidation_id") in consumed:
        errors.append("invalidation_already_consumed")
    if prior.get("receipt_id") not in record.get("invalidates", []):
        errors.append("invalidation does not identify the prior receipt")
    if record.get("action_scope_digest") != prior.get("action_key_scope_digest"):
        errors.append("invalidation action scope does not match prior receipt")
    for change in record.get("changes", []):
        if not isinstance(change, dict) or change.get("field") not in policy["allowed_changed_fields"] or change.get("before") == change.get("after"):
            errors.append("invalidation changes contain an invalid field or unchanged value")
    for evidence in record.get("evidence", []):
        if not isinstance(evidence, dict) or evidence.get("kind") not in policy["allowed_evidence_kinds"] or not valid_digest(evidence.get("digest")):
            errors.append("invalidation evidence is invalid")
    if record.get("reason_code") == "prior_evidence_corrupt" and not any(row.get("kind") == "verifier_report_digest" for row in record.get("evidence", []) if isinstance(row, dict)):
        errors.append("prior_evidence_corrupt requires verifier_report_digest")
    return errors


def load_receipts(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    receipts: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                receipts.append(value)
    return receipts


def rate_advisories(event: dict[str, Any]) -> list[dict[str, Any]]:
    rate = event.get("rate_telemetry")
    if not isinstance(rate, dict):
        return []
    return [{"state": rate.get("state"), "effect": "advisory"}]


def sanitized_metrics(event: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "status": row["status"],
            "value": row.get("value"),
            "unit": row["unit"],
            "source_ref": digest(row["source_ref"]) if row.get("source_ref") else None,
            "basis_receipt_ids": sorted(set(row.get("basis_receipt_ids", []))),
        }
        for row in event.get("metrics", [])
        if isinstance(row, dict)
    ]


def sanitized_progress(event: dict[str, Any]) -> dict[str, Any]:
    progress = event.get("material_progress", {"status": "unknown", "evidence_digest": None})
    return {"status": progress.get("status", "unknown"), "evidence_digest": progress.get("evidence_digest")}


def sanitized_fanout(event: dict[str, Any]) -> dict[str, Any] | None:
    fanout = event.get("fanout")
    if not isinstance(fanout, dict):
        return None
    return {
        "declared": True,
        "packet_id": digest(fanout.get("packet_id")),
        "session_id": digest(fanout.get("session_id")),
        "packet_owner_agent_id": digest(fanout.get("packet_owner_agent_id")),
        "integration_owner_agent_id": digest(fanout.get("integration_owner_agent_id")),
        "write_contract_digest": digest(fanout.get("write_contract")),
        "assignments_digest": digest(fanout.get("assignments")),
        "assignment_count": len(fanout.get("assignments", [])),
        "runtime_receipt_ref": digest(fanout.get("runtime_receipt_ref")),
    }


def build_receipt(event: dict[str, Any], prior_receipts: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    errors = validate_event(event, policy)
    if errors:
        raise ValueError("; ".join(errors))
    for receipt in prior_receipts:
        if receipt.get("event_id") == digest(event["event_id"]):
            return receipt
    key = work_key(event)
    fanout_errors = validate_fanout(event.get("fanout"))
    prior = next((row for row in reversed(prior_receipts) if key and row.get("work_key") == key and row.get("outcome") in {"pass", "reused", "local_failure"}), None)
    consumed = {item for row in prior_receipts for item in row.get("consumed_invalidation_ids", [])}
    invalidation_id = None
    consumed_now: list[str] = []
    if event.get("promotion_requested") is True:
        level = "promotion_gate"
        proof = event.get("promotion_evidence", {})
        ready = isinstance(proof, dict) and all(proof.get(field) is True for field in ("frozen_identity_complete", "targeted_checks_pass", "full_gate_pass", "package_integrity_pass", "authority_map_pass"))
        decision, reason, outcome = ("promotion_ready", "promotion_evidence_complete", "pass") if ready else ("promotion_not_ready", "promotion_evidence_incomplete", "not_ready")
    elif fanout_errors:
        level, decision, reason, outcome = "enforce", "block_this_local_action", "fanout_invalid", "blocked"
    elif key is None:
        level, decision, reason, outcome = "observe", "allow_with_advisory", "work_identity_incomplete", "pass"
    elif prior is None:
        level, decision, reason, outcome = "bypass", "allow", "first_equivalent_action", "pass"
    elif prior.get("outcome") == "local_failure":
        level, decision, reason, outcome = "enforce", "local_fix_required", "deterministic_local_failure", "blocked"
    else:
        record = event.get("invalidation")
        if record is not None:
            invalidation_errors = validate_invalidation(record, prior, consumed, policy)
            if not invalidation_errors:
                invalidation_id = record["invalidation_id"]
                consumed_now = [invalidation_id]
                level, decision, reason, outcome = "observe", "allow_reexecution", "typed_invalidation_consumed", "pass"
            else:
                level, decision, reason, outcome = "enforce", "block_this_local_action", invalidation_errors[0], "blocked"
        else:
            level, decision, reason, outcome = "enforce", "reuse_prior_evidence", "equivalent_passing_evidence_exists", "reused"
    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_id": "",
        "event_id": digest(event["event_id"]),
        "task_id": digest(event["task_id"]),
        "attempt_id": digest(event["attempt_id"]),
        "model_ref": digest(event["model_ref"]) if event.get("model_ref") else None,
        "policy_digest": event.get("policy_digest"),
        "candidate_digest": event.get("candidate_digest"),
        "dependency_digest": event.get("dependency_digest"),
        "action_key": action_key(event),
        "action_key_scope_digest": event.get("action_scope_digest"),
        "work_key": key,
        "intervention_level": level,
        "decision": decision,
        "reason_code": reason,
        "outcome": outcome,
        "evidence_digest": event.get("evidence_digest"),
        "invalidation_id": invalidation_id,
        "consumed_invalidation_ids": consumed_now,
        "fanout": sanitized_fanout(event),
        "material_progress": sanitized_progress(event),
        "rate_advisories": rate_advisories(event),
        "metrics": sanitized_metrics(event),
        "validator_version": "0.1.0",
        "fixture_corpus_version": "1",
    }
    receipt["receipt_id"] = digest({key: value for key, value in receipt.items() if key != "receipt_id"})
    return receipt


def verify_receipt(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    unknown = set(receipt) - set(RECEIPT_FIELDS) - {"action_key_scope_digest"}
    if unknown:
        errors.append(f"receipt contains unknown fields: {', '.join(sorted(unknown))}")
    lower_keys = {key.lower() for key in receipt}
    for key in lower_keys:
        if any(token in key for token in PROHIBITED_RECEIPT_KEYS):
            errors.append(f"receipt contains prohibited content field: {key}")
    expected = digest({key: value for key, value in receipt.items() if key != "receipt_id"})
    if receipt.get("receipt_id") != expected:
        errors.append("receipt_id checksum mismatch")
    if receipt.get("schema_version") != "1.0" or receipt.get("validator_version") != "0.1.0" or receipt.get("fixture_corpus_version") != "1":
        errors.append("receipt version fields are invalid")
    for field in ("receipt_id", "event_id", "task_id", "attempt_id", "model_ref", "policy_digest", "candidate_digest", "dependency_digest", "action_key", "action_key_scope_digest", "work_key", "evidence_digest", "invalidation_id"):
        if not valid_digest(receipt.get(field), nullable=True):
            errors.append(f"receipt {field} must be null or a sha256 digest")
    if receipt.get("intervention_level") not in INTERVENTION_LEVELS:
        errors.append("receipt intervention_level is invalid")
    if receipt.get("decision") not in DECISIONS:
        errors.append("receipt decision is invalid")
    if receipt.get("reason_code") not in REASON_CODES and not str(receipt.get("reason_code", "")).startswith("invalidation missing field:"):
        errors.append("receipt reason_code is invalid")
    if receipt.get("outcome") not in OUTCOMES:
        errors.append("receipt outcome is invalid")
    if any(not valid_digest(item) for item in receipt.get("consumed_invalidation_ids", [])):
        errors.append("receipt consumed_invalidation_ids must contain only digests")
    fanout = receipt.get("fanout")
    if isinstance(fanout, dict):
        for field in ("packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "runtime_receipt_ref"):
            if not valid_digest(fanout.get(field)):
                errors.append(f"receipt fanout {field} must be a sha256 digest")
        for field in ("write_contract_digest", "assignments_digest"):
            if not valid_digest(fanout.get(field)):
                errors.append(f"receipt fanout {field} must be a sha256 digest")
    progress = receipt.get("material_progress")
    if not isinstance(progress, dict) or set(progress) != {"status", "evidence_digest"} or progress.get("status") not in MATERIAL_PROGRESS_STATES or not valid_digest(progress.get("evidence_digest"), nullable=True):
        errors.append("receipt material_progress is invalid")
    advisories = receipt.get("rate_advisories")
    if not isinstance(advisories, list) or any(
        not isinstance(item, dict)
        or set(item) != {"state", "effect"}
        or item.get("state") not in load_policy()["rate_states"]
        or item.get("effect") != "advisory"
        for item in advisories
    ):
        errors.append("receipt rate_advisories are invalid")
    for metric in receipt.get("metrics", []):
        if set(metric) != {"name", "status", "value", "unit", "source_ref", "basis_receipt_ids"}:
            errors.append("receipt metric fields are invalid")
        if metric.get("status") in {"unknown", "stale"} and metric.get("value") is not None:
            errors.append("unknown/stale metric value must remain null")
        if not valid_digest(metric.get("source_ref"), nullable=True):
            errors.append("receipt metric source_ref must be null or a digest")
        if any(not valid_digest(item) for item in metric.get("basis_receipt_ids", [])):
            errors.append("receipt metric basis_receipt_ids must contain only digests")
    return errors


def verify_package(manifest_path: Path) -> list[str]:
    manifest = read_json(manifest_path)
    errors: list[str] = []
    root = manifest_path.parent.parent
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        return ["package manifest requires files"]
    material: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not row.get("path") or not row.get("sha256"):
            errors.append(f"package files[{index}] is incomplete")
            continue
        path = (root / str(row["path"])).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            errors.append(f"package files[{index}] escapes the plugin root")
            continue
        if not path.exists():
            errors.append(f"package file missing: {row['path']}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != row["sha256"]:
            errors.append(f"package file hash mismatch: {row['path']}")
        if path.stat().st_size != row.get("bytes"):
            errors.append(f"package file byte count mismatch: {row['path']}")
        material.append(f"{str(row['path']).replace(chr(92), '/')}|{actual}|{path.stat().st_size}")
    aggregate = hashlib.sha256("\n".join(sorted(material)).encode("utf-8")).hexdigest()
    if manifest.get("aggregate_algorithm") != "sha256_sorted_path_hash_bytes_v1":
        errors.append("package aggregate_algorithm is missing or invalid")
    if manifest.get("package_payload_sha256") != aggregate:
        errors.append("package_payload_sha256 mismatch")
    return errors


def append_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical(receipt) + "\n")


@contextmanager
def state_lock(path: Path):
    """Serialize state-file decisions across processes without a service or dependency."""

    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def decide_with_state(event: dict[str, Any], state: Path, policy: dict[str, Any]) -> dict[str, Any]:
    with state_lock(state):
        prior = load_receipts(state)
        receipt = build_receipt(event, prior, policy)
        errors = verify_receipt(receipt)
        if errors:
            raise ValueError("; ".join(errors))
        if not any(row.get("event_id") == receipt["event_id"] for row in prior):
            append_receipt(state, receipt)
        return receipt


def fixture_event(case: dict[str, Any]) -> dict[str, Any]:
    seed = case.get("seed", case["id"])
    base = {
        "schema_version": "1.0", "event_id": f"event-{seed}", "task_id": "fixture-task",
        "attempt_id": "attempt-1", "action_kind": case.get("action_kind", "targeted_test"),
        "action_scope_digest": digest({"scope": seed}), "requirements_digest": digest({"requirements": "v1"}),
        "candidate_digest": digest({"candidate": case.get("candidate", "v1")}),
        "dependency_digest": digest({"dependencies": "v1"}), "policy_digest": digest({"policy": "v1"}),
        "evaluator_digest": digest({"evaluator": "v1"}), "environment_digest": digest({"environment": "v1"}),
        "material_progress": {"status": "unknown", "evidence_digest": None},
        "rate_telemetry": {"state": case.get("rate_state", "below_80"), "effect": "advisory"}, "metrics": [],
    }
    base.update(case.get("event_overrides", {}))
    return base


def run_self_test(corpus: Path = CORPUS_PATH) -> dict[str, Any]:
    policy = load_policy()
    results: list[dict[str, Any]] = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        event = fixture_event(case)
        prior: list[dict[str, Any]] = []
        if case.get("prior") in {"pass_same", "local_failure_same"}:
            first = dict(event)
            first["event_id"] = f"setup-{case['id']}"
            setup = build_receipt(first, [], policy)
            if case["prior"] == "local_failure_same":
                setup["outcome"] = "local_failure"
                setup["receipt_id"] = digest({key: value for key, value in setup.items() if key != "receipt_id"})
            prior.append(setup)
        if case.get("invalidation") and prior:
            record = {
                "schema_version": "1.0", "invalidates": [prior[-1]["receipt_id"]],
                "action_scope_digest": event["action_scope_digest"], "reason_code": "transient_execution_failure",
                "changes": [{"field": "prior_evidence_status", "before": "pass", "after": "transient_failure"}],
                "evidence": [{"kind": "execution_trace_digest", "digest": digest({"trace": case["id"]})}],
                "issued_for_attempt_id": event["attempt_id"], "note": "fixture",
            }
            record["invalidation_id"] = invalidation_fingerprint(record)
            if case["invalidation"] == "free_text":
                event["invalidation"] = "code changed"
            elif case["invalidation"] == "consumed":
                prior[-1].setdefault("consumed_invalidation_ids", []).append(record["invalidation_id"])
                event["invalidation"] = record
            else:
                event["invalidation"] = record
        if case.get("repeat_event"):
            first = build_receipt(event, prior, policy)
            prior.append(first)
        try:
            receipt = build_receipt(event, prior, policy)
            actual = receipt["decision"]
        except ValueError:
            actual = "schema_rejection"
        passed = actual == case["expected_decision"]
        results.append({"id": case["id"], "expected": case["expected_decision"], "actual": actual, "passed": passed})
    return {"status": "pass" if all(item["passed"] for item in results) else "fail", "case_count": len(results), "results": results}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    decide = sub.add_parser("decide")
    decide.add_argument("--event", type=Path, required=True)
    decide.add_argument("--state", type=Path)
    decide.add_argument("--output", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    package = sub.add_parser("verify-package")
    package.add_argument("--manifest", type=Path, default=ROOT / "assets" / "package-manifest.json")
    test = sub.add_parser("self-test")
    test.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "decide":
        event = read_json(args.event)
        try:
            if args.state:
                receipt = decide_with_state(event, args.state, load_policy())
                errors: list[str] = []
            else:
                receipt = build_receipt(event, [], load_policy())
                errors = verify_receipt(receipt)
        except ValueError as exc:
            print(json.dumps({"status": "fail", "errors": [str(exc)]}, indent=2))
            return 1
        if errors:
            print(json.dumps({"status": "fail", "errors": errors}, indent=2))
            return 1
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "pass", "receipt": receipt}, indent=2))
        return 0
    if args.command == "verify":
        errors = verify_receipt(read_json(args.receipt))
        print(json.dumps({"status": "pass" if not errors else "fail", "errors": errors}, indent=2))
        return 0 if not errors else 1
    if args.command == "verify-package":
        errors = verify_package(args.manifest.resolve())
        print(json.dumps({"status": "pass" if not errors else "fail", "errors": errors}, indent=2))
        return 0 if not errors else 1
    result = run_self_test(args.corpus.resolve())
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
