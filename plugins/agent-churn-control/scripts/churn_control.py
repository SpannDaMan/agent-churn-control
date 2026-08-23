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
PACKAGE_TEXT_SUFFIXES = {".json", ".jsonl", ".ndjson", ".md", ".py", ".yaml", ".yml", ".svg"}
ACTION_KINDS = {"targeted_test", "broad_test", "premium_review", "retry", "tool_call", "panel", "plan_revision", "artifact", "promotion"}
MATERIAL_PROGRESS_STATES = {"yes", "no", "unknown"}
METRIC_STATUSES = {"measured", "derived", "unknown", "stale"}
INTERVENTION_LEVELS = {"bypass", "observe", "enforce", "promotion_gate"}
DECISIONS = {"allow", "allow_with_advisory", "allow_reexecution", "evidence_accepted", "reuse_prior_evidence", "local_fix_required", "block_this_local_action", "promotion_ready", "promotion_not_ready"}
OUTCOMES = {"pending", "pass", "reused", "blocked", "not_ready", "local_failure"}
REASON_CODES = {
    "first_equivalent_action", "rate_advisory_only", "work_identity_incomplete",
    "typed_invalidation_consumed", "equivalent_passing_evidence_exists",
    "deterministic_local_failure", "fanout_invalid", "promotion_evidence_complete",
    "promotion_evidence_incomplete", "promotion_identity_or_evidence_incomplete", "invalidation_already_consumed",
    "accepted_evidence_recorded", "equivalent_action_pending", "transient_retry_budget_exhausted",
    "accepted_evidence_without_matching_reservation",
    "exact_event_already_reserved", "changed_work_requires_typed_invalidation", "invalidation_invalid",
    "invalidation_transition_already_consumed", "invalidation_does_not_target_current_prior",
    "typed invalidation is required", "invalidation reason_code is not allowed",
    "invalidation_id does not match canonical fingerprint",
    "invalidation does not identify the prior receipt",
    "invalidation action scope does not match prior receipt",
    "invalidation changes contain an invalid field or unchanged value",
    "invalidation evidence is invalid", "prior_evidence_corrupt requires verifier_report_digest",
}
RECEIPT_FIELDS = [
    "schema_version", "receipt_id", "event_id", "event_fingerprint", "task_id", "attempt_id", "model_ref",
    "action_kind", "policy_digest", "requirements_digest", "candidate_digest", "dependency_digest",
    "evaluator_digest", "environment_digest", "environment_independent", "action_key", "action_key_scope_digest", "work_key",
    "intervention_level", "decision", "reason_code", "outcome", "evidence_digest",
    "reservation_receipt_id", "invalidation_id", "invalidation_reason_code", "invalidation_target_receipt_id",
    "invalidation_transition_id", "consumed_invalidation_ids", "evidence_accepted", "fanout", "material_progress",
    "rate_advisories", "metrics", "validator_version", "fixture_corpus_version",
]
EVENT_FIELDS = {
    "schema_version", "event_id", "task_id", "attempt_id", "model_ref", "action_kind",
    "action_scope_digest", "requirements_digest", "candidate_digest", "dependency_digest",
    "policy_digest", "evaluator_digest", "environment_digest", "environment_independent",
    "evidence_digest", "evidence_accepted", "evidence_outcome", "reservation_receipt_id",
    "material_progress", "promotion_requested", "promotion_evidence", "fanout", "invalidation",
    "rate_telemetry", "metrics",
}
INVALIDATION_REASON_FIELDS = {
    "candidate_changed": "candidate_digest",
    "dependency_changed": "dependency_digest",
    "policy_changed": "policy_digest",
    "requirements_changed": "requirements_digest",
    "scope_changed": "action_scope_digest",
    "evaluator_changed": "evaluator_digest",
    "environment_changed": "environment_digest",
    "transient_execution_failure": "prior_evidence_status",
    "prior_evidence_corrupt": "prior_evidence_status",
}


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
    unknown = set(event) - EVENT_FIELDS
    if unknown:
        errors.append(f"event contains unsupported fields: {', '.join(sorted(unknown))}")
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
    if not isinstance(event.get("action_kind"), str) or event.get("action_kind") not in ACTION_KINDS:
        errors.append("action_kind is invalid")
    for field in DIGEST_FIELDS:
        if field in event and not valid_digest(event.get(field), nullable=field in {"candidate_digest", "dependency_digest", "environment_digest"}):
            errors.append(f"invalid digest field: {field}")
    if event.get("policy_digest") != digest(policy):
        errors.append("policy_digest does not match the active policy")
    if "evidence_digest" in event and not valid_digest(event.get("evidence_digest"), nullable=True):
        errors.append("evidence_digest must be null or a sha256 digest")
    if "evidence_accepted" in event and not isinstance(event.get("evidence_accepted"), bool):
        errors.append("evidence_accepted must be boolean")
    if event.get("evidence_accepted") is True and not valid_digest(event.get("evidence_digest")):
        errors.append("accepted evidence requires evidence_digest")
    if event.get("evidence_outcome") not in (None, "pass", "local_failure"):
        errors.append("evidence_outcome must be pass or local_failure")
    if event.get("evidence_outcome") is not None and event.get("evidence_accepted") is not True:
        errors.append("evidence_outcome requires evidence_accepted")
    if not valid_digest(event.get("reservation_receipt_id"), nullable=True):
        errors.append("reservation_receipt_id must be null or a sha256 digest")
    if event.get("reservation_receipt_id") is not None and event.get("evidence_accepted") is not True:
        errors.append("reservation_receipt_id requires evidence_accepted")
    if event.get("promotion_requested") is True and event.get("evidence_outcome") == "local_failure":
        errors.append("promotion evidence cannot record local_failure")
    if "promotion_requested" in event and not isinstance(event.get("promotion_requested"), bool):
        errors.append("promotion_requested must be boolean")
    promotion_proof = event.get("promotion_evidence")
    if promotion_proof is not None and not isinstance(promotion_proof, dict):
        errors.append("promotion_evidence must be an object")
    if promotion_proof is not None and event.get("promotion_requested") is not True:
        errors.append("promotion_evidence requires promotion_requested true")
    if event.get("environment_digest") is not None and event.get("environment_independent") is True:
        errors.append("environment_digest and environment_independent are mutually exclusive")
    if "environment_independent" in event and event.get("environment_independent") is not True:
        errors.append("environment_independent must be true when supplied")
    rate = event.get("rate_telemetry")
    if rate is not None:
        if not isinstance(rate, dict) or set(rate) != {"state", "effect"} or rate.get("state") not in policy["rate_states"]:
            errors.append("rate_telemetry.state is invalid")
        elif rate.get("effect") != "advisory":
            errors.append("rate_telemetry.effect must be advisory")
    progress = event.get("material_progress", {"status": "unknown", "evidence_digest": None})
    if not isinstance(progress, dict) or set(progress) - {"status", "evidence_digest"}:
        errors.append("material_progress must contain only status and evidence_digest")
    elif not isinstance(progress.get("status"), str) or progress.get("status") not in MATERIAL_PROGRESS_STATES or not valid_digest(progress.get("evidence_digest"), nullable=True):
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
            if not isinstance(metric.get("status"), str) or metric.get("status") not in METRIC_STATUSES:
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


def event_fingerprint(event: dict[str, Any]) -> str:
    return digest({key: value for key, value in event.items() if key != "event_id"})


def validate_fanout(fanout: Any) -> list[str]:
    if fanout is None:
        return []
    if not isinstance(fanout, dict):
        return ["fanout must be an object or omitted"]
    if fanout.get("declared") is not True:
        return ["fanout object is allowed only when declared is true"]
    required = ["packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "write_contract", "assignments", "runtime_receipt_ref"]
    allowed = {"declared", *required}
    if set(fanout) != allowed:
        return ["fanout fields are invalid"]
    errors = [f"fanout missing field: {field}" for field in required if fanout.get(field) in (None, "", [])]
    if not isinstance(fanout.get("write_contract"), dict):
        errors.append("fanout write_contract must be an object")
    for field in ("packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "runtime_receipt_ref"):
        if fanout.get(field) and not valid_opaque_id(fanout.get(field)):
            errors.append(f"fanout {field} must be an opaque identifier")
    assignments = fanout.get("assignments", [])
    scopes: list[str] = []
    if not isinstance(assignments, list):
        errors.append("fanout assignments must be a list")
        return errors
    for row in assignments:
        if not isinstance(row, dict) or set(row) != {"agent_id", "write_scopes"} or not valid_opaque_id(row.get("agent_id")) or not isinstance(row.get("write_scopes"), list):
            errors.append("fanout assignment requires opaque agent_id and write_scopes list")
            continue
        if any(not valid_opaque_id(item) for item in row["write_scopes"]):
            errors.append("fanout write_scopes must contain opaque identifiers")
            continue
        scopes.extend(str(item) for item in row["write_scopes"])
    if len(scopes) != len(set(scopes)):
        errors.append("fanout write scopes must be disjoint")
    return errors


def invalidation_fingerprint(record: dict[str, Any]) -> str:
    payload = {
        "schema_version": record.get("schema_version"),
        "invalidates": sorted(record.get("invalidates", [])),
        "action_scope_digest": record.get("action_scope_digest"),
        "reason_code": record.get("reason_code"),
        "changes": sorted(record.get("changes", []), key=canonical),
        "evidence": sorted(record.get("evidence", []), key=canonical),
    }
    return digest(payload)


def identity_value(source: dict[str, Any], field: str, *, receipt: bool) -> Any:
    if field == "action_scope_digest":
        return source.get("action_key_scope_digest" if receipt else "action_scope_digest")
    if field == "prior_evidence_status":
        return source.get("outcome") if receipt else None
    return source.get(field)


def invalidation_target(record: Any, prior_receipts: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(record, dict) or not isinstance(record.get("invalidates"), list) or len(record["invalidates"]) != 1:
        return None
    target_id = record["invalidates"][0]
    return next((
        row for row in reversed(prior_receipts)
        if row.get("receipt_id") == target_id
        and (
            (row.get("outcome") in {"pass", "reused", "local_failure"} and row.get("evidence_accepted") is True)
            or (
                record.get("reason_code") == "transient_execution_failure"
                and row.get("decision") in {"allow", "allow_reexecution"}
                and row.get("outcome") == "pending"
            )
        )
    ), None)


def invalidation_transition_fingerprint(record: dict[str, Any], event: dict[str, Any]) -> str:
    return digest({
        "invalidates": record.get("invalidates"),
        "action_scope_digest": record.get("action_scope_digest"),
        "reason_code": record.get("reason_code"),
        "changes": sorted(record.get("changes", []), key=canonical),
        "current_work_key": work_key(event),
    })


def validate_invalidation(
    record: Any,
    prior: dict[str, Any] | None,
    consumed: set[str],
    policy: dict[str, Any],
    event: dict[str, Any] | None = None,
    consumed_transitions: set[str] | None = None,
) -> list[str]:
    if not isinstance(record, dict):
        return ["typed invalidation is required"]
    errors: list[str] = []
    required_fields = ("schema_version", "invalidation_id", "invalidates", "action_scope_digest", "reason_code", "changes", "evidence")
    allowed_fields = set(required_fields) | {"issued_for_attempt_id", "note"}
    unknown = set(record) - allowed_fields
    if unknown:
        errors.append(f"invalidation contains unsupported fields: {', '.join(sorted(unknown))}")
    for field in required_fields:
        if record.get(field) in (None, "", []):
            errors.append(f"invalidation missing field: {field}")
    if record.get("schema_version") != "1.0":
        errors.append("invalidation schema_version must be 1.0")
    invalidates = record.get("invalidates")
    changes = record.get("changes")
    evidence_rows = record.get("evidence")
    if not isinstance(invalidates, list) or len(invalidates) != 1 or any(not valid_digest(item) for item in invalidates):
        errors.append("invalidation invalidates must contain exactly one receipt digest")
    if not isinstance(changes, list) or not changes:
        errors.append("invalidation changes must be a non-empty list")
    if not isinstance(evidence_rows, list) or not evidence_rows:
        errors.append("invalidation evidence must be a non-empty list")
    if errors:
        return errors
    if prior is None or prior.get("receipt_id") != invalidates[0]:
        return ["invalidation does not identify the prior receipt"]
    reason_code = record.get("reason_code") if isinstance(record.get("reason_code"), str) else None
    if reason_code not in policy["allowed_invalidation_reasons"]:
        errors.append("invalidation reason_code is not allowed")
    if not valid_opaque_id(record.get("issued_for_attempt_id"), nullable=True):
        errors.append("invalidation issued_for_attempt_id must be null or an opaque identifier")
    if record.get("note") is not None and (not isinstance(record.get("note"), str) or len(record.get("note")) > 512):
        errors.append("invalidation note must be a string of at most 512 characters")
    if record.get("invalidation_id") != invalidation_fingerprint(record):
        errors.append("invalidation_id does not match canonical fingerprint")
    if isinstance(record.get("invalidation_id"), str) and record.get("invalidation_id") in consumed:
        errors.append("invalidation_already_consumed")
    if record.get("action_scope_digest") != prior.get("action_key_scope_digest"):
        errors.append("invalidation action scope does not match prior receipt")
    event_supplied = event is not None
    if event is None:
        event = {}
        prior = dict(prior)
        for change in changes:
            if not isinstance(change, dict):
                continue
            field = change.get("field")
            if field == "action_scope_digest":
                prior.setdefault("action_key_scope_digest", change.get("before"))
                event["action_scope_digest"] = change.get("after")
            elif field == "prior_evidence_status":
                prior.setdefault("outcome", change.get("before"))
            elif isinstance(field, str):
                prior.setdefault(field, change.get("before"))
                event[field] = change.get("after")
    transition_id = invalidation_transition_fingerprint(record, event)
    if consumed_transitions is not None and transition_id in consumed_transitions:
        errors.append("invalidation_transition_already_consumed")
    changed_fields: set[str] = set()
    for change in changes:
        if not isinstance(change, dict) or set(change) != {"field", "before", "after"} or change.get("field") not in policy["allowed_changed_fields"] or change.get("before") == change.get("after"):
            errors.append("invalidation changes contain an invalid field or unchanged value")
            continue
        field = change["field"]
        if field in changed_fields:
            errors.append("invalidation changes contain duplicate fields")
            continue
        changed_fields.add(field)
        expected_before = identity_value(prior, field, receipt=True)
        if field == "prior_evidence_status":
            expected_after = "transient_execution_failure" if reason_code == "transient_execution_failure" else "prior_evidence_corrupt"
        else:
            expected_after = identity_value(event, field, receipt=False)
        if change.get("before") != expected_before or change.get("after") != expected_after:
            errors.append("invalidation change does not match prior and current identity")
    required_changed_field = INVALIDATION_REASON_FIELDS.get(reason_code)
    if required_changed_field is not None and required_changed_field not in changed_fields:
        errors.append("invalidation reason_code does not match changed fields")
    state_reasons = {"transient_execution_failure", "prior_evidence_corrupt"}
    if reason_code in state_reasons and changed_fields != {"prior_evidence_status"}:
        errors.append("state invalidation may change only prior_evidence_status")
    if event_supplied and reason_code in state_reasons and valid_digest(prior.get("work_key"), nullable=True) and prior.get("work_key") is not None and work_key(event) != prior.get("work_key"):
        errors.append("state invalidation cannot change work identity")
    if reason_code not in state_reasons and "prior_evidence_status" in changed_fields:
        errors.append("identity invalidation cannot change prior_evidence_status")
    for evidence in evidence_rows:
        if not isinstance(evidence, dict) or set(evidence) != {"kind", "digest"} or evidence.get("kind") not in policy["allowed_evidence_kinds"] or not valid_digest(evidence.get("digest")):
            errors.append("invalidation evidence is invalid")
    expected_evidence: set[tuple[str, str]] = set()
    if reason_code == "transient_execution_failure":
        valid_rows = [row for row in evidence_rows if isinstance(row, dict) and row.get("kind") == "execution_trace_digest" and valid_digest(row.get("digest"))]
        if len(evidence_rows) != 1 or len(valid_rows) != 1:
            errors.append("transient invalidation requires exactly one execution trace")
    elif reason_code == "prior_evidence_corrupt":
        valid_rows = [row for row in evidence_rows if isinstance(row, dict) and row.get("kind") == "verifier_report_digest" and valid_digest(row.get("digest"))]
        if len(evidence_rows) != 1 or len(valid_rows) != 1:
            errors.append("prior evidence corruption requires exactly one verifier report")
    else:
        for field in changed_fields:
            if field == "prior_evidence_status":
                continue
            before_value = identity_value(prior, field, receipt=True)
            after_value = identity_value(event, field, receipt=False)
            evidence_digest = after_value if valid_digest(after_value) else digest({"field": field, "before": before_value, "after": after_value})
            expected_evidence.add((field, evidence_digest))
        actual_evidence = {
            (str(row.get("kind")), str(row.get("digest")))
            for row in evidence_rows
            if isinstance(row, dict) and set(row) == {"kind", "digest"} and valid_digest(row.get("digest"))
        }
        if actual_evidence != expected_evidence or len(evidence_rows) != len(expected_evidence):
            errors.append("invalidation evidence does not bind every changed identity")
    if reason_code == "prior_evidence_corrupt" and not any(row.get("kind") == "verifier_report_digest" for row in evidence_rows if isinstance(row, dict)):
        errors.append("prior_evidence_corrupt requires verifier_report_digest")
    return errors


def load_receipts(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    receipts: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"state line {line_number} must be a receipt object")
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
    assignments = fanout.get("assignments")
    return {
        "declared": True,
        "packet_id": digest(fanout.get("packet_id")),
        "session_id": digest(fanout.get("session_id")),
        "packet_owner_agent_id": digest(fanout.get("packet_owner_agent_id")),
        "integration_owner_agent_id": digest(fanout.get("integration_owner_agent_id")),
        "write_contract_digest": digest(fanout.get("write_contract")),
        "assignments_digest": digest(fanout.get("assignments")),
        "assignment_count": len(assignments) if isinstance(assignments, list) else 0,
        "runtime_receipt_ref": digest(fanout.get("runtime_receipt_ref")),
    }


def build_receipt(event: dict[str, Any], prior_receipts: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    errors = validate_event(event, policy)
    if errors:
        raise ValueError("; ".join(errors))
    for index, receipt in enumerate(prior_receipts):
        prior_errors = verify_receipt(receipt)
        if prior_errors:
            raise ValueError(f"invalid prior receipt[{index}]: {'; '.join(prior_errors)}")
    requested_fingerprint = event_fingerprint(event)
    for receipt in prior_receipts:
        if receipt.get("event_id") == digest(event["event_id"]):
            if receipt.get("event_fingerprint") != requested_fingerprint:
                raise ValueError("event_id_collision")
            if receipt.get("decision") in {"allow", "allow_with_advisory", "allow_reexecution"} and receipt.get("outcome") == "pending":
                replay = dict(receipt)
                replay.update({
                    "intervention_level": "enforce",
                    "decision": "block_this_local_action",
                    "reason_code": "exact_event_already_reserved",
                    "evidence_digest": None,
                    "reservation_receipt_id": None,
                    "evidence_accepted": False,
                })
                replay["receipt_id"] = digest({field: value for field, value in replay.items() if field != "receipt_id"})
                return replay
            return receipt
    key = work_key(event)
    fanout_errors = validate_fanout(event.get("fanout"))
    work_history = [row for row in prior_receipts if key and row.get("work_key") == key]
    settled_reservations = {
        row.get("reservation_receipt_id")
        for row in work_history
        if row.get("outcome") in {"pass", "local_failure"} and valid_digest(row.get("reservation_receipt_id"))
    }
    settled_reservations.update(
        row.get("invalidation_target_receipt_id")
        for row in work_history
        if row.get("decision") == "allow_reexecution" and valid_digest(row.get("invalidation_target_receipt_id"))
    )
    pending = next((
        row for row in reversed(work_history)
        if row.get("decision") in {"allow", "allow_reexecution"}
        and row.get("outcome") == "pending"
        and row.get("receipt_id") not in settled_reservations
    ), None)
    prior = next((row for row in reversed(work_history) if row.get("outcome") in {"pass", "reused", "local_failure"} and row.get("evidence_accepted") is True and valid_digest(row.get("evidence_digest"))), None)
    latest_scope_prior = next((
        row for row in reversed(prior_receipts)
        if key
        and row.get("task_id") == digest(event["task_id"])
        and row.get("action_kind") == event.get("action_kind")
        and row.get("action_key_scope_digest") == event.get("action_scope_digest")
        and row.get("outcome") in {"pass", "reused", "local_failure"}
        and row.get("evidence_accepted") is True
    ), None)
    related_changed_prior = next((
        row for row in reversed(prior_receipts)
        if key
        and row.get("work_key") != key
        and row.get("task_id") == digest(event["task_id"])
        and row.get("action_kind") == event.get("action_kind")
        and row.get("action_key_scope_digest") == event.get("action_scope_digest")
        and row.get("outcome") in {"pass", "reused", "local_failure"}
        and row.get("evidence_accepted") is True
    ), None)
    record = event.get("invalidation")
    latest_task_action_prior = next((
        row for row in reversed(prior_receipts)
        if key
        and row.get("task_id") == digest(event["task_id"])
        and row.get("action_kind") == event.get("action_kind")
        and row.get("outcome") in {"pass", "reused", "local_failure"}
        and row.get("evidence_accepted") is True
    ), None)
    target_prior = invalidation_target(record, prior_receipts)
    consumed = {item for row in prior_receipts for item in row.get("consumed_invalidation_ids", [])}
    consumed_transitions = {
        row.get("invalidation_transition_id")
        for row in prior_receipts
        if valid_digest(row.get("invalidation_transition_id"))
    }
    invalidation_id = None
    invalidation_reason_code = None
    invalidation_target_receipt_id = None
    invalidation_transition_id = None
    consumed_now: list[str] = []
    evidence_digest_value = None
    evidence_accepted_value = False
    reservation_receipt_id = event.get("reservation_receipt_id")
    if fanout_errors:
        level, decision, reason, outcome = "enforce", "block_this_local_action", "fanout_invalid", "blocked"
    elif event.get("promotion_requested") is True:
        level = "promotion_gate"
        proof = event.get("promotion_evidence", {})
        identity_ready = key is not None and valid_digest(event.get("candidate_digest")) and event.get("evidence_accepted") is True and valid_digest(event.get("evidence_digest"))
        proof_fields = {"frozen_identity_complete", "targeted_checks_pass", "full_gate_pass", "package_integrity_pass", "authority_map_pass"}
        proof_ready = isinstance(proof, dict) and set(proof) == proof_fields and all(proof.get(field) is True for field in proof_fields)
        ready = identity_ready and proof_ready
        reason = "promotion_evidence_complete" if ready else ("promotion_identity_or_evidence_incomplete" if not identity_ready else "promotion_evidence_incomplete")
        decision, outcome = ("promotion_ready", "pass") if ready else ("promotion_not_ready", "not_ready")
        evidence_accepted_value = ready
        evidence_digest_value = event.get("evidence_digest") if ready else None
        reservation_receipt_id = None
    elif key is None:
        level, decision, reason, outcome = "observe", "allow_with_advisory", "work_identity_incomplete", "pending"
    elif event.get("evidence_accepted") is True:
        reservation_matches = pending is not None and reservation_receipt_id == pending.get("receipt_id")
        if reservation_matches:
            evidence_digest_value = event.get("evidence_digest")
            evidence_accepted_value = True
            if event.get("evidence_outcome", "pass") == "local_failure":
                level, decision, reason, outcome = "enforce", "local_fix_required", "deterministic_local_failure", "local_failure"
            else:
                level, decision, reason, outcome = "observe", "evidence_accepted", "accepted_evidence_recorded", "pass"
        else:
            level, decision, reason, outcome = "enforce", "block_this_local_action", "accepted_evidence_without_matching_reservation", "blocked"
            reservation_receipt_id = None
    elif record is not None:
        relevant_prior = latest_scope_prior
        if isinstance(record, dict) and record.get("reason_code") == "scope_changed":
            relevant_prior = latest_task_action_prior
        if relevant_prior is not None and target_prior is not None and target_prior.get("receipt_id") != relevant_prior.get("receipt_id"):
            invalidation_errors = ["invalidation_does_not_target_current_prior"]
        elif pending is not None and isinstance(record, dict) and (record.get("reason_code") != "transient_execution_failure" or target_prior is None or target_prior.get("receipt_id") != pending.get("receipt_id")):
            invalidation_errors = ["equivalent_action_pending"]
        else:
            invalidation_errors = validate_invalidation(
                record,
                target_prior,
                consumed,
                policy,
                event=event,
                consumed_transitions=consumed_transitions,
            )
        if not invalidation_errors and record.get("reason_code") == "transient_execution_failure":
            transient_count = sum(1 for row in prior_receipts if row.get("work_key") == key and row.get("invalidation_reason_code") == "transient_execution_failure")
            if transient_count >= int(policy["max_transient_retries_per_work_key"]):
                invalidation_errors.append("transient_retry_budget_exhausted")
        if not invalidation_errors:
            invalidation_id = record["invalidation_id"]
            invalidation_reason_code = record["reason_code"]
            invalidation_target_receipt_id = target_prior["receipt_id"]
            invalidation_transition_id = invalidation_transition_fingerprint(record, event)
            consumed_now = [invalidation_id]
            level, decision, reason, outcome = "observe", "allow_reexecution", "typed_invalidation_consumed", "pending"
        else:
            first_error = invalidation_errors[0]
            reason = first_error if first_error in REASON_CODES or first_error.startswith("invalidation missing field:") else "invalidation_invalid"
            level, decision, outcome = "enforce", "block_this_local_action", "blocked"
    elif pending is not None:
        level, decision, reason, outcome = "enforce", "block_this_local_action", "equivalent_action_pending", "pending"
    elif prior is None and related_changed_prior is not None:
        level, decision, reason, outcome = "enforce", "block_this_local_action", "changed_work_requires_typed_invalidation", "blocked"
    elif prior is None:
        level, decision, reason, outcome = "bypass", "allow", "first_equivalent_action", "pending"
    elif prior.get("outcome") == "local_failure":
        level, decision, reason, outcome = "enforce", "local_fix_required", "deterministic_local_failure", "blocked"
    else:
        level, decision, reason, outcome = "enforce", "reuse_prior_evidence", "equivalent_passing_evidence_exists", "reused"
        evidence_digest_value = prior.get("evidence_digest")
        evidence_accepted_value = True
    if decision != "evidence_accepted" and outcome != "local_failure":
        reservation_receipt_id = None
    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_id": "",
        "event_id": digest(event["event_id"]),
        "event_fingerprint": requested_fingerprint,
        "task_id": digest(event["task_id"]),
        "attempt_id": digest(event["attempt_id"]),
        "model_ref": digest(event["model_ref"]) if event.get("model_ref") else None,
        "action_kind": event.get("action_kind"),
        "policy_digest": event.get("policy_digest"),
        "requirements_digest": event.get("requirements_digest"),
        "candidate_digest": event.get("candidate_digest"),
        "dependency_digest": event.get("dependency_digest"),
        "evaluator_digest": event.get("evaluator_digest"),
        "environment_digest": event.get("environment_digest"),
        "environment_independent": event.get("environment_independent") if event.get("environment_independent") is True else None,
        "action_key": action_key(event),
        "action_key_scope_digest": event.get("action_scope_digest"),
        "work_key": key,
        "intervention_level": level,
        "decision": decision,
        "reason_code": reason,
        "outcome": outcome,
        "evidence_digest": evidence_digest_value,
        "reservation_receipt_id": reservation_receipt_id,
        "invalidation_id": invalidation_id,
        "invalidation_reason_code": invalidation_reason_code,
        "invalidation_target_receipt_id": invalidation_target_receipt_id,
        "invalidation_transition_id": invalidation_transition_id,
        "consumed_invalidation_ids": consumed_now,
        "evidence_accepted": evidence_accepted_value,
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
    missing = set(RECEIPT_FIELDS) - set(receipt)
    unknown = set(receipt) - set(RECEIPT_FIELDS)
    if missing:
        errors.append(f"receipt is missing fields: {', '.join(sorted(missing))}")
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
    for field in ("receipt_id", "event_id", "event_fingerprint", "task_id", "attempt_id", "policy_digest", "requirements_digest", "evaluator_digest", "action_key", "action_key_scope_digest"):
        if not valid_digest(receipt.get(field)):
            errors.append(f"receipt {field} must be a sha256 digest")
    for field in ("model_ref", "candidate_digest", "dependency_digest", "environment_digest", "work_key", "evidence_digest", "reservation_receipt_id", "invalidation_id", "invalidation_target_receipt_id", "invalidation_transition_id"):
        if not valid_digest(receipt.get(field), nullable=True):
            errors.append(f"receipt {field} must be null or a sha256 digest")
    if not isinstance(receipt.get("action_kind"), str) or receipt.get("action_kind") not in ACTION_KINDS:
        errors.append("receipt action_kind is invalid")
    if receipt.get("environment_independent") not in (None, True):
        errors.append("receipt environment_independent must be true or null")
    if receipt.get("environment_digest") is not None and receipt.get("environment_independent") is True:
        errors.append("receipt environment identity is contradictory")
    expected_action_key = digest({"action_kind": receipt.get("action_kind"), "action_scope_digest": receipt.get("action_key_scope_digest")})
    if receipt.get("action_key") != expected_action_key:
        errors.append("receipt action_key does not match identity fields")
    identity = {
        "schema_version": receipt.get("schema_version"),
        "action_kind": receipt.get("action_kind"),
        "action_scope_digest": receipt.get("action_key_scope_digest"),
        "requirements_digest": receipt.get("requirements_digest"),
        "candidate_digest": receipt.get("candidate_digest"),
        "dependency_digest": receipt.get("dependency_digest"),
        "policy_digest": receipt.get("policy_digest"),
        "evaluator_digest": receipt.get("evaluator_digest"),
        "environment_digest": receipt.get("environment_digest"),
        "environment_independent": receipt.get("environment_independent"),
    }
    expected_work_key = None
    required_identity = ("schema_version", "action_kind", "action_scope_digest", "requirements_digest", "policy_digest", "evaluator_digest")
    if all(identity.get(field) for field in required_identity) and (identity.get("environment_digest") or identity.get("environment_independent") is True):
        expected_work_key = digest(identity)
    if receipt.get("work_key") != expected_work_key:
        errors.append("receipt work_key does not match identity fields")
    if not isinstance(receipt.get("intervention_level"), str) or receipt.get("intervention_level") not in INTERVENTION_LEVELS:
        errors.append("receipt intervention_level is invalid")
    if not isinstance(receipt.get("decision"), str) or receipt.get("decision") not in DECISIONS:
        errors.append("receipt decision is invalid")
    if not isinstance(receipt.get("reason_code"), str) or (receipt.get("reason_code") not in REASON_CODES and not receipt.get("reason_code", "").startswith("invalidation missing field:")):
        errors.append("receipt reason_code is invalid")
    if not isinstance(receipt.get("outcome"), str) or receipt.get("outcome") not in OUTCOMES:
        errors.append("receipt outcome is invalid")
    decision_outcomes = {
        "allow": {"pending"},
        "allow_with_advisory": {"pending"},
        "allow_reexecution": {"pending"},
        "evidence_accepted": {"pass"},
        "reuse_prior_evidence": {"reused"},
        "local_fix_required": {"blocked", "local_failure"},
        "block_this_local_action": {"blocked", "pending"},
        "promotion_ready": {"pass"},
        "promotion_not_ready": {"not_ready"},
    }
    receipt_decision = receipt.get("decision") if isinstance(receipt.get("decision"), str) else None
    receipt_outcome = receipt.get("outcome") if isinstance(receipt.get("outcome"), str) else None
    if receipt_decision in decision_outcomes and receipt_outcome not in decision_outcomes[receipt_decision]:
        errors.append("receipt decision and outcome are inconsistent")
    consumed_ids = receipt.get("consumed_invalidation_ids")
    if not isinstance(consumed_ids, list) or any(not valid_digest(item) for item in consumed_ids):
        errors.append("receipt consumed_invalidation_ids must contain only digests")
    invalidation_reason = receipt.get("invalidation_reason_code")
    if invalidation_reason is not None and invalidation_reason not in load_policy()["allowed_invalidation_reasons"]:
        errors.append("receipt invalidation_reason_code is invalid")
    if receipt.get("invalidation_id") is not None and invalidation_reason is None:
        errors.append("receipt invalidation_id requires invalidation_reason_code")
    if receipt.get("invalidation_id") is None and invalidation_reason is not None:
        errors.append("receipt invalidation_reason_code requires invalidation_id")
    if receipt.get("invalidation_id") is not None and consumed_ids != [receipt.get("invalidation_id")]:
        errors.append("receipt invalidation consumption must match invalidation_id")
    if receipt.get("invalidation_id") is None and consumed_ids != []:
        errors.append("receipt cannot consume an invalidation without invalidation_id")
    if receipt.get("invalidation_id") is not None and (not valid_digest(receipt.get("invalidation_target_receipt_id")) or not valid_digest(receipt.get("invalidation_transition_id"))):
        errors.append("receipt invalidation requires target and transition digests")
    if receipt.get("invalidation_id") is None and (receipt.get("invalidation_target_receipt_id") is not None or receipt.get("invalidation_transition_id") is not None):
        errors.append("receipt invalidation target and transition require invalidation_id")
    if not isinstance(receipt.get("evidence_accepted"), bool):
        errors.append("receipt evidence_accepted must be boolean")
    if receipt_outcome in {"pass", "reused", "local_failure"} and (receipt.get("evidence_accepted") is not True or not valid_digest(receipt.get("evidence_digest"))):
        errors.append("accepted receipt outcome requires accepted evidence digest")
    if receipt_outcome in {"pending", "blocked", "not_ready"} and (receipt.get("evidence_accepted") is not False or receipt.get("evidence_digest") is not None):
        errors.append("unaccepted receipt outcome cannot contain accepted evidence")
    if receipt.get("decision") == "evidence_accepted" and not valid_digest(receipt.get("reservation_receipt_id")):
        errors.append("accepted evidence receipt requires reservation_receipt_id")
    if receipt.get("outcome") == "local_failure" and not valid_digest(receipt.get("reservation_receipt_id")):
        errors.append("local failure receipt requires reservation_receipt_id")
    if receipt_decision not in {"evidence_accepted", "local_fix_required"} and receipt.get("reservation_receipt_id") is not None:
        errors.append("receipt reservation_receipt_id is not allowed for this decision")
    fanout = receipt.get("fanout")
    if fanout is not None and not isinstance(fanout, dict):
        errors.append("receipt fanout must be null or an object")
    elif isinstance(fanout, dict):
        expected_fanout = {"declared", "packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "write_contract_digest", "assignments_digest", "assignment_count", "runtime_receipt_ref"}
        if set(fanout) != expected_fanout or fanout.get("declared") is not True:
            errors.append("receipt fanout fields are invalid")
        for field in ("packet_id", "session_id", "packet_owner_agent_id", "integration_owner_agent_id", "runtime_receipt_ref"):
            if not valid_digest(fanout.get(field)):
                errors.append(f"receipt fanout {field} must be a sha256 digest")
        for field in ("write_contract_digest", "assignments_digest"):
            if not valid_digest(fanout.get(field)):
                errors.append(f"receipt fanout {field} must be a sha256 digest")
        if isinstance(fanout.get("assignment_count"), bool) or not isinstance(fanout.get("assignment_count"), int) or fanout.get("assignment_count") < 0:
            errors.append("receipt fanout assignment_count must be a non-negative integer")
    progress = receipt.get("material_progress")
    if not isinstance(progress, dict) or set(progress) != {"status", "evidence_digest"} or not isinstance(progress.get("status"), str) or progress.get("status") not in MATERIAL_PROGRESS_STATES or not valid_digest(progress.get("evidence_digest"), nullable=True):
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
    metrics = receipt.get("metrics")
    policy = load_policy()
    if not isinstance(metrics, list):
        errors.append("receipt metrics must be a list")
        metrics = []
    for metric in metrics:
        if not isinstance(metric, dict) or set(metric) != {"name", "status", "value", "unit", "source_ref", "basis_receipt_ids"}:
            errors.append("receipt metric fields are invalid")
            continue
        if metric.get("name") not in policy["allowed_metric_names"] or metric.get("unit") not in policy["allowed_metric_units"] or not isinstance(metric.get("status"), str) or metric.get("status") not in METRIC_STATUSES:
            errors.append("receipt metric enum value is invalid")
        metric_status = metric.get("status") if isinstance(metric.get("status"), str) else None
        if metric_status in {"unknown", "stale"} and metric.get("value") is not None:
            errors.append("unknown/stale metric value must remain null")
        if metric_status in {"measured", "derived"} and (isinstance(metric.get("value"), bool) or not isinstance(metric.get("value"), (int, float)) or not math.isfinite(float(metric.get("value")))):
            errors.append("measured/derived metric value must be finite numeric")
        if not valid_digest(metric.get("source_ref"), nullable=True):
            errors.append("receipt metric source_ref must be null or a digest")
        basis = metric.get("basis_receipt_ids")
        if not isinstance(basis, list) or any(not valid_digest(item) for item in basis):
            errors.append("receipt metric basis_receipt_ids must contain only digests")
        elif metric_status == "derived" and not basis:
            errors.append("derived receipt metric requires basis_receipt_ids")
        elif any(token in str(metric.get("name", "")) for token in ("saved", "avoided", "cost_of_pass")) and metric_status in {"measured", "derived"} and not basis:
            errors.append("numeric savings receipt metric requires basis_receipt_ids")
    return errors


def package_file_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.suffix.lower() in PACKAGE_TEXT_SUFFIXES:
        return raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return raw


def verify_package(manifest_path: Path) -> list[str]:
    manifest = read_json(manifest_path)
    errors: list[str] = []
    root = manifest_path.parent.parent
    expected_manifest_fields = {
        "schema_version", "plugin_id", "version", "release_state", "aggregate_algorithm",
        "package_payload_sha256", "files", "authority_map_path", "fixture_corpus_version",
        "validator_version", "publication_or_installation_authorized",
    }
    if set(manifest) != expected_manifest_fields:
        errors.append("package manifest fields are invalid")
    if manifest.get("schema_version") != "1.0" or manifest.get("plugin_id") != "agent-churn-control" or manifest.get("version") != "0.1.0":
        errors.append("package manifest identity is invalid")
    if manifest.get("release_state") not in {"public_release_candidate", "published"}:
        errors.append("package release_state is invalid")
    if manifest.get("authority_map_path") != "assets/authority-map.json" or manifest.get("fixture_corpus_version") != "1" or manifest.get("validator_version") != "0.1.0":
        errors.append("package manifest contract versions are invalid")
    if manifest.get("publication_or_installation_authorized") is not True:
        errors.append("package publication authorization is missing")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        return ["package manifest requires files"]
    row_paths = [str(row.get("path", "")).replace("\\", "/") for row in rows if isinstance(row, dict)]
    listed_paths = set(row_paths)
    if len(row_paths) != len(listed_paths):
        errors.append("package manifest contains duplicate paths")
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.resolve() != manifest_path.resolve()
    }
    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append(f"symlink not allowed in package: {path.relative_to(root).as_posix()}")
    for extra in sorted(actual_paths - listed_paths):
        errors.append(f"unlisted package file: {extra}")
    material: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "bytes"} or not row.get("path") or not row.get("sha256"):
            errors.append(f"package files[{index}] is incomplete")
            continue
        if not isinstance(row.get("bytes"), int) or isinstance(row.get("bytes"), bool) or row.get("bytes") < 0:
            errors.append(f"package files[{index}] bytes must be a non-negative integer")
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
        raw = package_file_bytes(path)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != row["sha256"]:
            errors.append(f"package file hash mismatch: {row['path']}")
        if len(raw) != row.get("bytes"):
            errors.append(f"package file byte count mismatch: {row['path']}")
        material.append(f"{str(row['path']).replace(chr(92), '/')}|{actual}|{len(raw)}")
    aggregate = hashlib.sha256("\n".join(sorted(material)).encode("utf-8")).hexdigest()
    if manifest.get("aggregate_algorithm") != "sha256_sorted_path_canonical_hash_bytes_v2":
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


def build_acceptance_event(event: dict[str, Any], reservation: dict[str, Any], evidence_digest: str, outcome: str) -> dict[str, Any]:
    reservation_errors = verify_receipt(reservation)
    if reservation_errors:
        raise ValueError(f"invalid reservation receipt: {'; '.join(reservation_errors)}")
    if reservation.get("outcome") != "pending" or reservation.get("decision") not in {"allow", "allow_reexecution"}:
        raise ValueError("reservation receipt is not an executable pending action")
    if work_key(event) != reservation.get("work_key"):
        raise ValueError("reservation receipt does not match event work identity")
    if not valid_digest(evidence_digest):
        raise ValueError("evidence_digest must be a sha256 digest")
    if outcome not in {"pass", "local_failure"}:
        raise ValueError("outcome must be pass or local_failure")
    acceptance = dict(event)
    acceptance.pop("promotion_requested", None)
    acceptance.pop("promotion_evidence", None)
    acceptance["event_id"] = "accept-" + digest({
        "reservation_receipt_id": reservation["receipt_id"],
        "evidence_digest": evidence_digest,
        "outcome": outcome,
    })[7:39]
    acceptance["evidence_accepted"] = True
    acceptance["evidence_digest"] = evidence_digest
    acceptance["evidence_outcome"] = outcome
    acceptance["reservation_receipt_id"] = reservation["receipt_id"]
    return acceptance


def fixture_event(case: dict[str, Any]) -> dict[str, Any]:
    seed = case.get("seed", case["id"])
    base = {
        "schema_version": "1.0", "event_id": f"event-{seed}", "task_id": "fixture-task",
        "attempt_id": "attempt-1", "action_kind": case.get("action_kind", "targeted_test"),
        "action_scope_digest": digest({"scope": seed}), "requirements_digest": digest({"requirements": "v1"}),
        "candidate_digest": digest({"candidate": case.get("candidate", "v1")}),
        "dependency_digest": digest({"dependencies": "v1"}), "policy_digest": digest(load_policy()),
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
            reservation_event = dict(event)
            reservation_event["event_id"] = f"setup-reservation-{case['id']}"
            reservation = build_receipt(reservation_event, [], policy)
            acceptance_event = dict(event)
            acceptance_event["event_id"] = f"setup-acceptance-{case['id']}"
            acceptance_event["evidence_accepted"] = True
            acceptance_event["evidence_digest"] = digest({"accepted": case["id"]})
            acceptance_event["reservation_receipt_id"] = reservation["receipt_id"]
            if case["prior"] == "local_failure_same":
                acceptance_event["evidence_outcome"] = "local_failure"
            setup = build_receipt(acceptance_event, [reservation], policy)
            prior.extend([reservation, setup])
        if case.get("invalidation") and prior:
            record = {
                "schema_version": "1.0", "invalidates": [prior[-1]["receipt_id"]],
                "action_scope_digest": event["action_scope_digest"], "reason_code": "transient_execution_failure",
                "changes": [{"field": "prior_evidence_status", "before": prior[-1]["outcome"], "after": "transient_execution_failure"}],
                "evidence": [{"kind": "execution_trace_digest", "digest": digest({"trace": case["id"]})}],
                "issued_for_attempt_id": event["attempt_id"], "note": "fixture",
            }
            record["invalidation_id"] = invalidation_fingerprint(record)
            if case["invalidation"] == "free_text":
                event["invalidation"] = "code changed"
            elif case["invalidation"] == "consumed":
                marker_event = dict(event)
                marker_event["event_id"] = f"marker-{case['id']}"
                marker_event["invalidation"] = record
                marker = build_receipt(marker_event, prior, policy)
                prior.append(marker)
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
    accept = sub.add_parser("accept")
    accept.add_argument("--event", type=Path, required=True)
    accept.add_argument("--reservation", type=Path, required=True)
    accept.add_argument("--evidence-digest", required=True)
    accept.add_argument("--outcome", choices=("pass", "local_failure"), default="pass")
    accept.add_argument("--state", type=Path, required=True)
    accept.add_argument("--output", type=Path)
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
        try:
            event = read_json(args.event)
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
    if args.command == "accept":
        try:
            acceptance = build_acceptance_event(read_json(args.event), read_json(args.reservation), args.evidence_digest, args.outcome)
            receipt = decide_with_state(acceptance, args.state, load_policy())
        except ValueError as exc:
            print(json.dumps({"status": "fail", "errors": [str(exc)]}, indent=2))
            return 1
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "pass", "receipt": receipt}, indent=2))
        return 0
    if args.command == "verify":
        try:
            errors = verify_receipt(read_json(args.receipt))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"status": "fail", "errors": [str(exc)]}, indent=2))
            return 1
        print(json.dumps({"status": "pass" if not errors else "fail", "errors": errors}, indent=2))
        return 0 if not errors else 1
    if args.command == "verify-package":
        try:
            errors = verify_package(args.manifest.resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"status": "fail", "errors": [str(exc)]}, indent=2))
            return 1
        print(json.dumps({"status": "pass" if not errors else "fail", "errors": errors}, indent=2))
        return 0 if not errors else 1
    result = run_self_test(args.corpus.resolve())
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
