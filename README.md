# AgentGuard AI

A small, dependency-free Python gate for AI-agent tools: **deny by default, require human
approval for selected actions, and record local audit events**.

This production-oriented starter implements a secure MVP foundation. It is early software,
not independently audited. The core engine does not execute arbitrary shell commands, authenticate users
or sandbox agents. The optional local dashboard adds single-reviewer password login. See [the security model](docs/SECURITY_MODEL.md).

## What works

- Exact policy matching with deny > approval > allow precedence.
- Immutable action snapshots and deterministic SHA-256 fingerprints.
- Human approval tied to the action, principal and policy; configurable expiry (1–3600s).
- Reviewer allowlist, self-approval prevention and atomic single-use consumption.
- Durable SQLite state and metadata audit records; safe concurrent consumption.
- Python API, local operator CLI, example, standard-library tests and GitHub Actions CI.

## Quick start

Requires Python 3.11+. Run from this repository directory.

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/demo.py
```

The demo prints the exact review payload, approves using a demo trusted operator identity,
executes a harmless handler and demonstrates replay prevention. It makes no network calls.

## Local approval dashboard (development preview)

A password-protected reviewer interface is included for local evaluation. It lists requests,
shows the exact action payload, supports approve/deny decisions and displays audit events.
It binds to `127.0.0.1` and never executes tools.

```sh
python -m agentguard.dashboard init
python -m agentguard.dashboard serve --demo
```

Create a password when prompted, open **http://127.0.0.1:8765**, sign in and inspect the demo
request. Use Approve or Deny, then check Audit history. This is an early local preview, not
a public hosting server. See [Windows setup and authentication details](docs/DASHBOARD.md).

## Full approval-to-execution demo

Keep the local dashboard running. In a second terminal, from this project folder:

```sh
python -m agentguard.demo_runner
```

The runner creates a fresh request and waits. Inspect that request in the dashboard and
approve it: a fixed harmless message prints in the runner terminal, and execution events
appear in audit history. Deny a new request to verify that nothing runs. No shell commands,
external messages or output files are produced by the tool. See the
[two-window Windows walkthrough](docs/DEMO_RUNNER.md).

## Local CLI

On POSIX first set `umask 077`; on Windows set private NTFS permissions for the state folder.

```sh
agentguard init
agentguard check examples/action.json
# Expected: approval, exit code 2 (the shell commands below remain separate).
agentguard request examples/action.json --ttl 300
# Copy the returned request_id in place of REQUEST_ID:
agentguard inspect REQUEST_ID
agentguard --reviewer operator review REQUEST_ID --as operator --approve
agentguard audit
```

Omit `--approve` to deny a request. Inspect the **entire payload**, resource and principal
before approving. Request IDs are not sufficient authority to execute; the state, policy,
reviewer and fingerprint are rechecked by the API. The CLI intentionally has no execution
command; real execution belongs in a trusted application integration.

CLI `check` exits 0 for allow, 2 for approval/deny; operational errors exit 1.
Other successful commands exit 0. `--policy`, `--db`, and `--reviewer` precede the subcommand.
Flags identify local trusted configuration, not authenticated identities.

## Python integration

```python
from agentguard import Action, Decision, Engine, Policy, Rule

policy = Policy((
    Rule("notes.publish", "notes/demo", "worker", Decision.APPROVAL),
))
# Create/protect this directory before starting the trusted service.
engine = Engine(".agentguard/state.sqlite3", policy, reviewers={"operator"})
action = Action("notes.publish", "notes/demo", "worker", {"text": "Hello"})
request_id = engine.request(action, ttl=300)

# Display engine.inspect(request_id) in your trusted reviewer UI.
# Only after authenticating the actual reviewer and obtaining their decision:
engine.review(request_id, reviewer="operator", approve=True)

# Replace this harmless handler with a narrow schema-validated tool adapter.
result = engine.execute(
    action,
    lambda approved: approved.parameters["text"],
    request_id=request_id,
)
```

Get identities from your trusted authentication layer. Never let the agent set the reviewer,
policy, reviewer allowlist, database path or real tool adapter. Route every protected tool
through `execute`. `Action.parameters` returns a copy; changing it never changes the action.

`request` only accepts actions whose policy decision is approval. `execute` raises
`ApprovalError` for blocked actions. Allowed actions need no approval ID and may execute
repeatedly. Approval consumption happens **before** the handler; failures burn the approval.
A handler side effect can succeed even if recording its final audit event fails. Reconcile
external state before retrying. See the security model for concurrency and crash semantics.

## Policy format

See [examples/policy.json](examples/policy.json). Every field is mandatory; unknown fields,
duplicate JSON keys, non-finite numbers and malformed types are rejected by the CLI loaders.
Matching is exact and case-sensitive. There are no globs or automatic path normalization.
Rules authorize the entire parameter space for a tuple; handlers must enforce schemas.
No match means deny. An explicit deny cannot be overridden by a human approval.

## Project layout

```text
src/agentguard/   Public API, policy, SQLite engine, CLI
tests/           Authorization, state, parsing, concurrency and CLI regression tests
examples/        Safe demo, sample policy and action
docs/            Threat model and operational limits
.github/         CI for Python 3.11–3.14 and package validation
```

## Build and publish source to GitHub

```sh
python -m pip install build twine
python -m build
python -m twine check dist/*
git init -b main
git add .
git commit -m "Add AgentGuard AI secure MVP"
git remote add origin https://github.com/YOUR_USERNAME/agentguard-ai.git
git push -u origin main
```

Create the empty public GitHub repository first. If it already contains files, clone it and
copy these project files into the checkout, review the diff, then commit; do not force-push.
The package metadata name does not reserve the corresponding name on PyPI. No publishing
credentials, hosted services or external account setup are included.

## Next milestones

1. Integrate an authenticated reviewer UI and narrow tool adapters.
2. Add parameter constraint policies, revocation and schema migrations.
3. Add protected remote audit export and operational metrics.
4. Release after integration testing and an independent security review.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT licensed.
