# Decisions and Receipts

## Work identity

The canonical work key binds the action kind, action scope, requirements, candidate, dependencies, policy, evaluator, and environment identity. Task IDs, attempt IDs, timestamps, notes, and caller-generated UUIDs do not make equivalent work new.

Provide either an `environment_digest` or `environment_independent: true`. Omitting both keeps identity incomplete and prevents evidence reuse.

## Decisions

- `allow`: first complete equivalent action.
- `allow_with_advisory`: identity is incomplete.
- `reuse_prior_evidence`: accepted equivalent evidence already exists.
- `allow_reexecution`: a valid typed invalidation authorizes one changed-work pass.
- `local_fix_required`: a deterministic local failure needs repair before retry.
- `block_this_local_action`: the named action is malformed or lacks valid invalidation.
- `promotion_ready` or `promotion_not_ready`: frozen-candidate evidence is complete or incomplete.

## Receipt privacy

External identifiers are stored as SHA-256 digests. Metrics use bounded names, statuses, units, numeric values, nulls, and digest references. Unknown and stale values remain null.

Receipts are local evidence, not runtime model proof, publication authority, or a guaranteed-savings statement.
