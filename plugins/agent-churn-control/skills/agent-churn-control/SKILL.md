---
name: agent-churn-control
description: Prevent duplicate agent work with a local provider-neutral decision core. Use before repeating tests, reviews, plans, retries, tool calls, panels, or promotion gates; when evidence may be reusable; when rate-limit efficiency matters; or when a task needs a bypass, observe, enforce, or promotion-readiness decision without granting external authority.
---

# Agent Churn Control

Use the bundled local CLI to decide whether a specific agent action should run, reuse prior evidence, be repaired locally, or wait at a promotion gate.

Keep material progress separate from churn. Material output can prove progress; it is not a churn dimension.

## Quick Start

1. Resolve `PLUGIN_ROOT` from this loaded `SKILL.md`: it is the directory two levels above the skill directory (`skills/agent-churn-control/../..`). Use that exact absolute path; never resolve plugin files from the user's project working directory.
2. Create an event from `<PLUGIN_ROOT>/assets/sample-event.json`.
3. Run `python "<PLUGIN_ROOT>/scripts/churn_control.py" decide --event <event.json> --state .agent-churn-control/receipts.ndjson --output <reservation.json>`.
4. After the action actually completes, run `python "<PLUGIN_ROOT>/scripts/churn_control.py" accept --event <event.json> --reservation <reservation.json> --evidence-digest <sha256:digest> --state .agent-churn-control/receipts.ndjson --output <accepted.json>`.
5. Run `python "<PLUGIN_ROOT>/scripts/churn_control.py" verify --receipt <accepted.json>` for a saved receipt, `python "<PLUGIN_ROOT>/scripts/churn_control.py" verify-package` for package integrity, or `python "<PLUGIN_ROOT>/scripts/churn_control.py" self-test` for the versioned fixture corpus.

An `allow` decision is a pending reservation, never proof that the action passed. Only the `accept` transition can attach an evidence digest and make the result reusable. The state path is serialized with a zero-dependency cross-process lock and re-read before append. Concurrent callers sharing the same state file therefore cannot both claim the first equivalent action.

## Intervention Levels

- `bypass`: first solo non-promotion action with complete identity; reserve and run it with no user-authored plan or ledger.
- `observe`: record linked accepted evidence, report incomplete identity, or permit one valid typed invalidation.
- `enforce`: equivalent accepted evidence exists, a deterministic failure needs local repair, or declared fan-out is malformed; block only that duplicate local action.
- `promotion_gate`: verify frozen candidate evidence and readiness; never publish or install.

## Required Identity

Provide digests for action scope, requirements, policy, and evaluator. Provide candidate and dependency digests when the action depends on them. For environment identity, provide either `environment_digest` or the explicit declaration `environment_independent: true`; omission leaves identity incomplete and cannot authorize evidence reuse. Task and attempt IDs join receipts but do not make identical work new. Every externally supplied identifier is hashed before receipt retention.

## Evidence Rules

- Reuse only a verified, accepted receipt for the same work key.
- Never treat a pending reservation as passing evidence; link acceptance to the exact reservation receipt.
- Do not repeat equivalent work because the attempt ID, timestamp, note, or caller-generated UUID changed.
- Use typed, single-use invalidation for a repeated action after a transient failure or proven evidence corruption.
- Keep unknown metrics unknown. Do not convert missing usage or cost to zero.
- Count prevented duplicate executions. Claim token, time, or money avoidance only from comparable authoritative basis receipts.
- Use `assets/sample-efficiency-measurement.json` as the content-free measured/unknown example; it is not a guaranteed-savings claim.

## Conditional Fan-Out

Omit `fanout` for solo work. When `fanout.declared` is true, provide packet ID, session ID, owner, integration owner, write contract, assignments, and receipt reference. The core never requires multi-agent metadata for solo work.

## Authority Boundary

This skill may classify local actions, emit advisories, append content-free local receipts, reuse valid evidence, gate a duplicate helper action, and validate promotion readiness.

It may not stop the overall task, publish, install, spend, change credentials, permissions, or scopes, recruit participants, perform external actions, or expose prompts, outputs, source contents, secrets, or absolute paths in receipts.

## Guardrails

- Rate telemetry is advisory at every percentage, including 100%, missing, or stale.
- One justified frozen-candidate full gate is allowed and reused on unchanged replay.
- Deterministic schema, receipt, checksum, packaging, local-test, verifier, and capture failures require local repair, not premium review.
- A core `enforce` decision applies only to the named local action; it is not authority to terminate work.
- Synthetic fixtures and focus groups are engineering evidence, not user-demand proof.
