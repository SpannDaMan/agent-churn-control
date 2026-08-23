# Threat Model

## Protected assets

- private prompts, outputs, source content, paths, credentials, and identities;
- correct work-equivalence and invalidation decisions;
- receipt integrity and replay behavior;
- package and policy integrity.

## Trust boundaries

Anti-Churn trusts the local Python runtime, the event producer, the selected state path, and the packaged policy bytes. It does not trust free-form invalidation prose, changed attempt IDs, timestamps, arbitrary receipt fields, or unverified package contents.

## Primary threats

1. Content leakage through allowed receipt values.
2. False reuse because work identity omits a material dimension.
3. Duplicate first-action decisions from concurrent callers.
4. Replay or reuse of a consumed invalidation.
5. Package tampering or stale sample evidence.
6. Host software treating a local decision as broader execution authority.

## Controls

- digest-only external identifiers;
- strict event and receipt fields;
- explicit environment identity or independence;
- canonical work keys and receipt checksums;
- typed, prior-bound, single-use invalidation;
- cross-process state lock and state re-read;
- versioned fixtures and package integrity verification;
- authority map limiting every decision to the named local action.

## Non-goals

The plugin does not sandbox the host, authenticate users, encrypt the local state file, prevent a malicious local administrator, execute models, prove provider state, or guarantee savings.
