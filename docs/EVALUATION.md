# Evaluation

## Versioned corpus

`plugins/agent-churn-control/fixtures/v1/corpus.ndjson` contains twenty-three deterministic cases covering first action, evidence reuse, attempts, replay, deterministic failure, typed invalidation, consumed invalidation, rate states, fan-out, promotion, unknown metrics, timeout, rate-limit retry, and partial results.

Run:

```text
python plugins/agent-churn-control/scripts/churn_control.py self-test
```

The command returns the expected decision, actual decision, and pass state for every case.

## Unit tests

```text
python -B -m pytest -q -p no:cacheprovider
```

Tests cover receipt privacy, environment identity, exact replay, concurrent state decisions, nested values, fan-out ownership, package authority, and the complete fixture corpus.

## Evidence boundary

Synthetic cases establish deterministic behavior for the tested contracts. They do not establish user demand, production savings, or universal performance across agent frameworks.
