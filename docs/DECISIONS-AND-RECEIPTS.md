# Decisions and Receipts

## Work identity

The canonical work key binds the action kind, action scope, requirements, candidate, dependencies, policy, evaluator, and environment identity. Task IDs, attempt IDs, timestamps, notes, and caller-generated UUIDs do not make equivalent work new.

Provide either an `environment_digest` or `environment_independent: true`. Omitting both keeps identity incomplete and prevents evidence reuse.

## Decisions

- `allow`: first complete equivalent action.
- `allow_with_advisory`: identity is incomplete.
- `evidence_accepted`: the action completed and accepted evidence was linked to its pending reservation.
- `reuse_prior_evidence`: accepted equivalent evidence already exists.
- `allow_reexecution`: a typed invalidation bound to the prior receipt and actual identity delta authorizes one changed-work pass.
- `local_fix_required`: a deterministic local failure needs repair before retry.
- `block_this_local_action`: the named action is malformed or lacks valid invalidation.
- `promotion_ready` or `promotion_not_ready`: frozen-candidate evidence is complete or incomplete.

## Receipt privacy

An `allow`, `allow_with_advisory`, or `allow_reexecution` receipt remains `pending`. It cannot be reused. The `accept` command verifies the pending reservation, preserves the same work identity, and emits a separately checksummed receipt with `evidence_accepted: true` and a content-free evidence digest. Exact replay of a pending event returns a local duplicate-action block; a later distinct action request must use a new event ID.

External identifiers are stored as SHA-256 digests. Metrics use bounded names, statuses, units, numeric values, nulls, and digest references. Unknown and stale values remain null.

Receipts are local evidence, not runtime model proof, publication authority, or a guaranteed-savings statement.
