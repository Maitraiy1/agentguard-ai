# Contributing

Start with a small issue describing the problem, intended behavior and security implications.
Security vulnerabilities belong in GitHub private vulnerability reporting, when enabled,
rather than public issues (see SECURITY.md).

## Development

Use Python 3.11 or later. There are no runtime or test dependencies.

```sh
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/demo.py
```

Use the standard library where practical, type public interfaces and keep changes focused.
Add regression tests for state transitions, authorization and concurrency changes.
Never submit credentials, real customer payloads, generated databases or virtual environments.

PRs should describe the problem, final behavior, security implications and commands tested.
All CI jobs must pass. Keep the default-deny behavior and fail-closed storage semantics.
Schema changes require an explicit migration plan; do not silently reinterpret old state.

By submitting a contribution you agree that it is licensed under the project's MIT license.

## Browser and security changes

For dashboard/authentication changes, install the optional browser extra and run the Chromium
walkthrough described in README.md. CI stores test-only screenshots and video artifacts.
For policy/state changes, cover revocation, stale workers, migration rollback and storage
failure. Explain any schema change and upgrade behavior. Never weaken checks to make tests pass.

AI-assisted contributions are welcome. State what changed and how you actually verified it;
do not claim an independent audit, users or test results that did not occur. Maintainers must
review generated code and remain responsible for changes. Genuine bugs, platform permission
tests, accessibility and operational documentation are useful contribution areas.
