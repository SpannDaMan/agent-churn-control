# Contributing

Contributions are welcome when they preserve the plugin's narrow product boundary.

## Before opening a pull request

1. Open or reference a focused issue for material behavior changes.
2. Keep the runtime standard-library-only.
3. Add or update a versioned fixture for behavior changes.
4. Preserve content-free receipts and advisory-only rate telemetry.
5. Run:

```text
python -B -m pytest -q -p no:cacheprovider
python plugins/agent-churn-control/scripts/churn_control.py self-test
python plugins/agent-churn-control/scripts/churn_control.py verify-package
python tools/validate_release_candidate.py
```

Do not include secrets, private prompts, local absolute paths, generated cache files, or customer data.

## Product boundary

Proposals for hosted telemetry, model routing, schedulers, databases, authentication, or external write authority belong in separate products unless a maintainer explicitly accepts a scope change.
