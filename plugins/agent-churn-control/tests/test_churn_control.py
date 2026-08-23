from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "churn_control.py"
SPEC = importlib.util.spec_from_file_location("agent_churn_control", MODULE_PATH)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)
POLICY = core.load_policy()


def event(seed: str = "one") -> dict:
    return {
        "schema_version": "1.0",
        "event_id": f"event-{seed}",
        "task_id": "task-1",
        "attempt_id": "attempt-1",
        "action_kind": "targeted_test",
        "action_scope_digest": core.digest({"scope": seed}),
        "requirements_digest": core.digest({"requirements": "v1"}),
        "candidate_digest": core.digest({"candidate": "v1"}),
        "dependency_digest": core.digest({"dependencies": "v1"}),
        "policy_digest": core.digest(POLICY),
        "evaluator_digest": core.digest({"evaluator": "v1"}),
        "environment_digest": core.digest({"environment": "v1"}),
        "material_progress": {"status": "unknown", "evidence_digest": None},
        "rate_telemetry": {"state": "below_80", "effect": "advisory"},
        "metrics": [],
    }


def test_versioned_corpus_exposes_a_verdict_for_every_case() -> None:
    result = core.run_self_test()
    expected_ids = [json.loads(line)["id"] for line in core.CORPUS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert result["status"] == "pass"
    assert result["case_count"] == len(expected_ids)
    assert [row["id"] for row in result["results"]] == expected_ids
    assert all(row["passed"] and row["actual"] == row["expected"] for row in result["results"])


def test_first_solo_action_bypasses_with_no_plan_or_fanout() -> None:
    receipt = core.build_receipt(event(), [], POLICY)
    assert receipt["intervention_level"] == "bypass"
    assert receipt["decision"] == "allow"
    assert receipt["fanout"] is None


def test_rate_states_are_advisory_only() -> None:
    for state in ("at_or_above_80", "at_or_above_97", "at_or_above_100", "missing", "stale"):
        value = event(state)
        value["rate_telemetry"] = {"state": state, "effect": "advisory"}
        receipt = core.build_receipt(value, [], POLICY)
        assert receipt["intervention_level"] == "bypass"
        assert receipt["decision"] == "allow"
        assert receipt["outcome"] == "pass"
        assert receipt["rate_advisories"] == [{"state": state, "effect": "advisory"}]


def test_attempt_id_does_not_make_equivalent_work_new() -> None:
    first = core.build_receipt(event(), [], POLICY)
    second_event = event()
    second_event["event_id"] = "event-two"
    second_event["attempt_id"] = "attempt-2"
    second = core.build_receipt(second_event, [first], POLICY)
    assert second["work_key"] == first["work_key"]
    assert second["decision"] == "reuse_prior_evidence"


def test_replay_is_idempotent() -> None:
    first = core.build_receipt(event(), [], POLICY)
    replay = core.build_receipt(event(), [first], POLICY)
    assert replay == first


def test_receipt_rejects_content_bearing_fields() -> None:
    receipt = core.build_receipt(event(), [], POLICY)
    receipt["prompt"] = "secret content"
    errors = core.verify_receipt(receipt)
    assert any("prohibited content field" in item for item in errors)


def test_allowed_receipt_fields_reject_content_or_path_like_values() -> None:
    value = event()
    value["task_id"] = "raw prompt text with spaces"
    assert any("opaque" in item for item in core.validate_event(value, POLICY))
    value = event()
    value["model_ref"] = "C:\\private\\model.txt"
    assert any("model_ref" in item for item in core.validate_event(value, POLICY))
    value = event()
    value["metrics"] = [{"name": "input_tokens", "status": "measured", "value": 10, "unit": "tokens", "source_ref": "C:\\secret\\receipt.json", "basis_receipt_ids": []}]
    assert any("source_ref" in item for item in core.validate_event(value, POLICY))


def test_all_external_identifiers_are_digested_in_receipts() -> None:
    value = event()
    value.update({"event_id": "secret", "task_id": "customer-name", "attempt_id": "attempt-private", "model_ref": "provider:model@revision"})
    receipt = core.build_receipt(value, [], POLICY)
    for field in ("event_id", "task_id", "attempt_id", "model_ref"):
        assert core.valid_digest(receipt[field])
        assert value[field] not in json.dumps(receipt)


def test_nested_receipt_values_are_typed_and_content_free() -> None:
    value = event()
    value["material_progress"] = {"status": "yes", "evidence_digest": core.digest({"evidence": "accepted"})}
    value["metrics"] = [{"name": "input_tokens", "status": "measured", "value": 100, "unit": "tokens", "source_ref": "meter-1", "basis_receipt_ids": []}]
    receipt = core.build_receipt(value, [], POLICY)
    assert receipt["material_progress"] == value["material_progress"]
    assert core.valid_digest(receipt["metrics"][0]["source_ref"])
    assert "meter-1" not in json.dumps(receipt)
    invalid = event()
    invalid["material_progress"] = {"status": "yes", "evidence_digest": None, "note": "raw content"}
    assert any("material_progress" in item for item in core.validate_event(invalid, POLICY))


def test_unknown_metric_never_becomes_zero() -> None:
    value = event()
    value["metrics"] = [{"name": "cost_of_pass", "status": "unknown", "value": None, "unit": "usd", "source_ref": None, "basis_receipt_ids": []}]
    receipt = core.build_receipt(value, [], POLICY)
    assert receipt["metrics"][0]["value"] is None


def test_distinct_packet_and_integration_owners_are_valid() -> None:
    value = event()
    value["fanout"] = {
        "declared": True,
        "packet_id": "packet-1",
        "session_id": "session-1",
        "packet_owner_agent_id": "reviewer-1",
        "integration_owner_agent_id": "root-1",
        "write_contract": {"mode": "read_only"},
        "assignments": [{"agent_id": "reviewer-1", "write_scopes": []}],
        "runtime_receipt_ref": "receipt-1",
    }
    assert core.validate_fanout(value["fanout"]) == []
    receipt = core.build_receipt(value, [], POLICY)
    assert receipt["decision"] == "allow"
    assert receipt["fanout"]["packet_owner_agent_id"] == core.digest("reviewer-1")
    assert receipt["fanout"]["integration_owner_agent_id"] == core.digest("root-1")


def test_environment_digest_is_part_of_work_identity() -> None:
    first = event()
    second = event()
    second["environment_digest"] = core.digest({"environment": "v2"})
    assert core.work_key(first) != core.work_key(second)


def test_missing_environment_identity_cannot_reuse_evidence() -> None:
    value = event()
    value.pop("environment_digest")
    receipt = core.build_receipt(value, [], POLICY)
    assert receipt["work_key"] is None
    assert receipt["intervention_level"] == "observe"
    assert receipt["reason_code"] == "work_identity_incomplete"
    value["environment_independent"] = True
    complete = core.build_receipt(value, [], POLICY)
    assert core.valid_digest(complete["work_key"])
    assert complete["intervention_level"] == "bypass"


def test_state_decision_is_atomic_across_concurrent_processes() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / "receipts.ndjson"
        processes = []
        for index in range(3):
            payload = event()
            payload["event_id"] = f"concurrent-{index}"
            event_path = root / f"event-{index}.json"
            event_path.write_text(json.dumps(payload), encoding="utf-8")
            processes.append(subprocess.Popen([sys.executable, str(MODULE_PATH), "decide", "--event", str(event_path), "--state", str(state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        outputs = [process.communicate(timeout=30) for process in processes]
        assert all(process.returncode == 0 for process in processes)
        decisions = [json.loads(stdout)["receipt"]["decision"] for stdout, _ in outputs]
        assert decisions.count("allow") == 1
        assert decisions.count("reuse_prior_evidence") == 2
        assert len(core.load_receipts(state)) == 3


def test_package_verification_normalizes_text_line_endings(tmp_path: Path) -> None:
    lf_path = tmp_path / "lf.ndjson"
    crlf_path = tmp_path / "crlf.ndjson"
    lf_path.write_bytes(b'{"value":1}\n')
    crlf_path.write_bytes(b'{"value":1}\r\n')
    assert core.package_file_bytes(lf_path) == core.package_file_bytes(crlf_path)


def test_skill_and_policy_dimension_contract_match() -> None:
    skill = (ROOT / "skills" / "agent-churn-control" / "SKILL.md").read_text(encoding="utf-8")
    assert "material progress separate from churn" in skill.lower()
    assert POLICY["churn_dimensions"] == core.load_policy()["churn_dimensions"]
    assert "planning_churn" in POLICY["churn_dimensions"]
    assert "material_output_delta" not in POLICY["churn_dimensions"]


def test_authority_map_forbids_external_effects() -> None:
    authority = json.loads((ROOT / "assets" / "authority-map.json").read_text(encoding="utf-8"))
    for value in ("publish", "install", "spend", "change_credentials", "change_permissions", "change_scopes", "perform_external_action"):
        assert value in authority["may_not"]
