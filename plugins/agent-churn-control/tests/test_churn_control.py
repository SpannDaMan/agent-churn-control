from __future__ import annotations

import importlib.util
import hashlib
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


def accepted_chain(seed: str = "one", *, outcome: str = "pass") -> list[dict]:
    reservation = core.build_receipt(event(seed), [], POLICY)
    acceptance = event(seed)
    acceptance["event_id"] = f"accepted-{seed}"
    acceptance["attempt_id"] = "attempt-acceptance"
    acceptance["evidence_accepted"] = True
    acceptance["evidence_digest"] = core.digest({"evidence": seed, "outcome": outcome})
    acceptance["reservation_receipt_id"] = reservation["receipt_id"]
    if outcome != "pass":
        acceptance["evidence_outcome"] = outcome
    accepted = core.build_receipt(acceptance, [reservation], POLICY)
    return [reservation, accepted]


def transient_invalidation(prior: dict, seed: str) -> dict:
    value = {
        "schema_version": "1.0",
        "invalidates": [prior["receipt_id"]],
        "action_scope_digest": prior["action_key_scope_digest"],
        "reason_code": "transient_execution_failure",
        "changes": [{"field": "prior_evidence_status", "before": prior["outcome"], "after": "transient_execution_failure"}],
        "evidence": [{"kind": "execution_trace_digest", "digest": core.digest({"trace": seed})}],
    }
    value["invalidation_id"] = core.invalidation_fingerprint(value)
    return value


def reseal(receipt: dict) -> None:
    receipt["receipt_id"] = core.digest({key: value for key, value in receipt.items() if key != "receipt_id"})


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
    assert receipt["outcome"] == "pending"
    assert receipt["evidence_accepted"] is False
    assert receipt["fanout"] is None


def test_rate_states_are_advisory_only() -> None:
    for state in ("at_or_above_80", "at_or_above_97", "at_or_above_100", "missing", "stale"):
        value = event(state)
        value["rate_telemetry"] = {"state": state, "effect": "advisory"}
        receipt = core.build_receipt(value, [], POLICY)
        assert receipt["intervention_level"] == "bypass"
        assert receipt["decision"] == "allow"
        assert receipt["outcome"] == "pending"
        assert receipt["rate_advisories"] == [{"state": state, "effect": "advisory"}]


def test_attempt_id_does_not_make_equivalent_work_new() -> None:
    history = accepted_chain()
    first = history[-1]
    second_event = event()
    second_event["event_id"] = "event-two"
    second_event["attempt_id"] = "attempt-2"
    second = core.build_receipt(second_event, history, POLICY)
    assert second["work_key"] == first["work_key"]
    assert second["decision"] == "reuse_prior_evidence"


def test_replay_is_idempotent() -> None:
    first = core.build_receipt(event(), [], POLICY)
    replay = core.build_receipt(event(), [first], POLICY)
    assert replay["decision"] == "block_this_local_action"
    assert replay["reason_code"] == "exact_event_already_reserved"
    assert replay["event_id"] == first["event_id"]
    assert core.verify_receipt(replay) == []


def test_evidence_is_reusable_only_after_linked_acceptance() -> None:
    reservation = core.build_receipt(event(), [], POLICY)
    duplicate = event()
    duplicate["event_id"] = "event-duplicate"
    blocked = core.build_receipt(duplicate, [reservation], POLICY)
    assert blocked["decision"] == "block_this_local_action"
    assert blocked["reason_code"] == "equivalent_action_pending"

    acceptance = event()
    acceptance.update({
        "event_id": "event-acceptance",
        "evidence_accepted": True,
        "evidence_digest": core.digest({"test": "passed"}),
        "reservation_receipt_id": reservation["receipt_id"],
    })
    accepted = core.build_receipt(acceptance, [reservation], POLICY)
    assert accepted["decision"] == "evidence_accepted"
    assert accepted["outcome"] == "pass"

    later = event()
    later["event_id"] = "event-later"
    reused = core.build_receipt(later, [reservation, accepted], POLICY)
    assert reused["decision"] == "reuse_prior_evidence"
    assert reused["evidence_digest"] == accepted["evidence_digest"]


def test_accepted_evidence_requires_the_latest_reservation() -> None:
    reservation = core.build_receipt(event(), [], POLICY)
    acceptance = event()
    acceptance.update({
        "event_id": "event-bad-acceptance",
        "evidence_accepted": True,
        "evidence_digest": core.digest({"test": "passed"}),
        "reservation_receipt_id": core.digest({"reservation": "wrong"}),
    })
    receipt = core.build_receipt(acceptance, [reservation], POLICY)
    assert receipt["decision"] == "block_this_local_action"
    assert receipt["reason_code"] == "accepted_evidence_without_matching_reservation"
    assert receipt["evidence_accepted"] is False


def test_acceptance_event_builder_links_identity_and_evidence() -> None:
    source = event()
    reservation = core.build_receipt(source, [], POLICY)
    evidence_digest = core.digest({"test": "passed"})
    acceptance = core.build_acceptance_event(source, reservation, evidence_digest, "pass")
    assert acceptance["reservation_receipt_id"] == reservation["receipt_id"]
    assert acceptance["evidence_digest"] == evidence_digest
    assert acceptance["evidence_accepted"] is True
    assert core.work_key(acceptance) == reservation["work_key"]


def test_blocked_duplicate_does_not_replace_the_active_reservation() -> None:
    source = event()
    reservation = core.build_receipt(source, [], POLICY)
    duplicate_event = event()
    duplicate_event["event_id"] = "event-duplicate-before-acceptance"
    duplicate = core.build_receipt(duplicate_event, [reservation], POLICY)
    acceptance = core.build_acceptance_event(source, reservation, core.digest({"test": "passed"}), "pass")
    accepted = core.build_receipt(acceptance, [reservation, duplicate], POLICY)
    assert accepted["decision"] == "evidence_accepted"
    assert accepted["reservation_receipt_id"] == reservation["receipt_id"]


def test_prior_receipts_must_pass_full_verification() -> None:
    fake = {"work_key": core.work_key(event()), "outcome": "pass"}
    try:
        core.build_receipt(event("next"), [fake], POLICY)
    except ValueError as exc:
        assert "invalid prior receipt" in str(exc)
    else:
        raise AssertionError("malformed prior receipt was accepted")


def test_event_id_collision_is_rejected() -> None:
    first_event = event()
    first = core.build_receipt(first_event, [], POLICY)
    collision = event()
    collision["candidate_digest"] = core.digest({"candidate": "different"})
    try:
        core.build_receipt(collision, [first], POLICY)
    except ValueError as exc:
        assert "event_id_collision" in str(exc)
    else:
        raise AssertionError("event_id collision returned stale evidence")


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


def test_fanout_assignments_must_be_a_list() -> None:
    value = event()
    value["fanout"] = {
        "declared": True,
        "packet_id": "packet-1",
        "session_id": "session-1",
        "packet_owner_agent_id": "reviewer-1",
        "integration_owner_agent_id": "root-1",
        "write_contract": {"mode": "read_only"},
        "assignments": {"reviewer-1": []},
        "runtime_receipt_ref": "receipt-1",
    }
    assert "fanout assignments must be a list" in core.validate_fanout(value["fanout"])
    receipt = core.build_receipt(value, [], POLICY)
    assert receipt["decision"] == "block_this_local_action"


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
        assert decisions.count("block_this_local_action") == 2
        assert len(core.load_receipts(state)) == 3


def test_identical_concurrent_event_id_has_one_executor() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / "receipts.ndjson"
        event_path = root / "event.json"
        event_path.write_text(json.dumps(event()), encoding="utf-8")
        processes = [
            subprocess.Popen([sys.executable, "-B", str(MODULE_PATH), "decide", "--event", str(event_path), "--state", str(state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(3)
        ]
        outputs = [process.communicate(timeout=30) for process in processes]
        assert all(process.returncode == 0 for process in processes)
        decisions = [json.loads(stdout)["receipt"]["decision"] for stdout, _ in outputs]
        assert decisions.count("allow") == 1
        assert decisions.count("block_this_local_action") == 2
        assert len(core.load_receipts(state)) == 1


def test_malformed_invalidation_collections_are_rejected_without_crashing() -> None:
    history = accepted_chain()
    value = event()
    value["event_id"] = "event-malformed-invalidation"
    value["invalidation"] = {
        "schema_version": "1.0",
        "invalidation_id": core.digest({"invalid": True}),
        "invalidates": {"not": "a-list"},
        "action_scope_digest": history[-1]["action_key_scope_digest"],
        "reason_code": "transient_execution_failure",
        "changes": {"not": "a-list"},
        "evidence": {"not": "a-list"},
    }
    receipt = core.build_receipt(value, history, POLICY)
    assert receipt["decision"] == "block_this_local_action"
    assert receipt["reason_code"] == "invalidation_invalid"
    assert core.verify_receipt(receipt) == []


def test_changed_candidate_invalidation_binds_across_work_keys() -> None:
    history = accepted_chain()
    changed = event()
    changed["event_id"] = "event-candidate-v2"
    changed["candidate_digest"] = core.digest({"candidate": "v2"})
    record = {
        "schema_version": "1.0",
        "invalidates": [history[-1]["receipt_id"]],
        "action_scope_digest": history[-1]["action_key_scope_digest"],
        "reason_code": "candidate_changed",
        "changes": [{"field": "candidate_digest", "before": history[-1]["candidate_digest"], "after": changed["candidate_digest"]}],
        "evidence": [{"kind": "candidate_digest", "digest": changed["candidate_digest"]}],
    }
    record["invalidation_id"] = core.invalidation_fingerprint(record)
    changed["invalidation"] = record
    receipt = core.build_receipt(changed, history, POLICY)
    assert receipt["work_key"] != history[-1]["work_key"]
    assert receipt["decision"] == "allow_reexecution"
    assert core.verify_receipt(receipt) == []


def test_changed_candidate_requires_typed_invalidation() -> None:
    history = accepted_chain()
    changed = event()
    changed["event_id"] = "event-candidate-v2-untyped"
    changed["candidate_digest"] = core.digest({"candidate": "v2"})
    receipt = core.build_receipt(changed, history, POLICY)
    assert receipt["decision"] == "block_this_local_action"
    assert receipt["reason_code"] == "changed_work_requires_typed_invalidation"


def test_fabricated_invalidation_delta_is_rejected() -> None:
    history = accepted_chain()
    value = event()
    value["event_id"] = "event-fabricated-delta"
    record = {
        "schema_version": "1.0",
        "invalidates": [history[-1]["receipt_id"]],
        "action_scope_digest": history[-1]["action_key_scope_digest"],
        "reason_code": "candidate_changed",
        "changes": [{"field": "candidate_digest", "before": core.digest("invented-before"), "after": core.digest("invented-after")}],
        "evidence": [{"kind": "candidate_digest", "digest": core.digest("invented-after")}],
    }
    record["invalidation_id"] = core.invalidation_fingerprint(record)
    value["invalidation"] = record
    receipt = core.build_receipt(value, history, POLICY)
    assert receipt["decision"] == "block_this_local_action"
    assert receipt["reason_code"] == "invalidation_invalid"


def test_transient_retry_budget_is_per_work_key() -> None:
    history = accepted_chain()
    retry = event()
    retry["event_id"] = "retry-one"
    retry["invalidation"] = transient_invalidation(history[-1], "one")
    reservation = core.build_receipt(retry, history, POLICY)
    assert reservation["decision"] == "allow_reexecution"

    acceptance = event()
    acceptance.update({
        "event_id": "retry-one-accepted",
        "evidence_accepted": True,
        "evidence_digest": core.digest({"retry": "one", "status": "pass"}),
        "reservation_receipt_id": reservation["receipt_id"],
    })
    accepted = core.build_receipt(acceptance, [*history, reservation], POLICY)

    second_retry = event()
    second_retry["event_id"] = "retry-two"
    second_retry["invalidation"] = transient_invalidation(accepted, "two")
    blocked = core.build_receipt(second_retry, [*history, reservation, accepted], POLICY)
    assert blocked["decision"] == "block_this_local_action"
    assert blocked["reason_code"] == "transient_retry_budget_exhausted"


def test_receipt_verifier_enforces_complete_nested_schema() -> None:
    receipt = core.build_receipt(event(), [], POLICY)
    missing = dict(receipt)
    missing.pop("policy_digest")
    reseal(missing)
    assert any("missing fields" in item for item in core.verify_receipt(missing))

    null_required = dict(receipt)
    null_required["policy_digest"] = None
    reseal(null_required)
    assert any("policy_digest must be a sha256 digest" in item for item in core.verify_receipt(null_required))

    nested = dict(receipt)
    nested["fanout"] = {
        "declared": True,
        "packet_id": core.digest("packet"),
        "session_id": core.digest("session"),
        "packet_owner_agent_id": core.digest("owner"),
        "integration_owner_agent_id": core.digest("integration"),
        "write_contract_digest": core.digest("contract"),
        "assignments_digest": core.digest("assignments"),
        "assignment_count": 1,
        "runtime_receipt_ref": core.digest("runtime"),
        "prompt": "raw text",
    }
    reseal(nested)
    assert any("fanout fields are invalid" in item for item in core.verify_receipt(nested))

    metric = dict(receipt)
    metric["metrics"] = [{"name": "input_tokens", "status": "measured", "value": "10", "unit": "tokens", "source_ref": None, "basis_receipt_ids": []}]
    reseal(metric)
    assert any("finite numeric" in item for item in core.verify_receipt(metric))

    derived = dict(receipt)
    derived["metrics"] = [{"name": "avoided_work_units", "status": "derived", "value": 1, "unit": "work_units", "source_ref": None, "basis_receipt_ids": []}]
    reseal(derived)
    assert any("requires basis_receipt_ids" in item for item in core.verify_receipt(derived))


def test_rejected_acceptance_shapes_still_emit_valid_receipts() -> None:
    history = accepted_chain()
    malformed = event()
    malformed.update({
        "event_id": "malformed-acceptance",
        "evidence_accepted": True,
        "evidence_digest": core.digest("evidence"),
        "reservation_receipt_id": history[0]["receipt_id"],
        "fanout": {"declared": True},
    })
    receipt = core.build_receipt(malformed, history, POLICY)
    assert receipt["decision"] == "block_this_local_action"
    assert receipt["reservation_receipt_id"] is None
    assert core.verify_receipt(receipt) == []


def test_package_verification_normalizes_text_line_endings(tmp_path: Path) -> None:
    lf_path = tmp_path / "lf.ndjson"
    crlf_path = tmp_path / "crlf.ndjson"
    lf_path.write_bytes(b'{"value":1}\n')
    crlf_path.write_bytes(b'{"value":1}\r\n')
    assert core.package_file_bytes(lf_path) == core.package_file_bytes(crlf_path)


def test_package_verifier_rejects_unlisted_files(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    assets = plugin / "assets"
    scripts = plugin / "scripts"
    assets.mkdir(parents=True)
    scripts.mkdir()
    payload = scripts / "core.py"
    payload.write_text("print('ok')\n", encoding="utf-8", newline="\n")
    raw = core.package_file_bytes(payload)
    row = {"path": "scripts/core.py", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    aggregate = hashlib.sha256(f"scripts/core.py|{row['sha256']}|{row['bytes']}".encode("utf-8")).hexdigest()
    manifest = assets / "package-manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": "1.0",
        "aggregate_algorithm": "sha256_sorted_path_canonical_hash_bytes_v2",
        "package_payload_sha256": aggregate,
        "files": [row],
    }), encoding="utf-8")
    (plugin / "UNLISTED.md").write_text("unexpected\n", encoding="utf-8")
    assert "unlisted package file: UNLISTED.md" in core.verify_package(manifest)


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
