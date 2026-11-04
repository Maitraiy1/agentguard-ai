# Validation record

Validated on 4 November 2026 with CPython 3.12.14 on Linux.

- Built a wheel and source archive using the local setuptools PEP 517 backend.
- Installed the wheel into a separate virtual environment without runtime dependencies.
- Ran `python -m unittest discover -s tests -v` against the installed wheel: **25 tests passed**.
- Ran `python examples/demo.py`: approved execution succeeded and replay was blocked.
- Ran installed `agentguard --help`: entry point loaded successfully.
- Checked wheel ZIP integrity, package metadata, MIT license declaration and type marker.
- Checked that the source archive contains the regression tests.

Tests cover default deny, rule precedence, strict inputs, immutable snapshots, action and
principal substitution, expiry, unauthorized/self review, denial, reviewer revocation,
policy changes, replay, concurrent consumption, handler failure, persistence, unsupported
schema versions and database failure both before and after a side effect, plus CLI flow.

GitHub Actions is configured for Python 3.11–3.14 on Linux and Windows; remote jobs have not been run here.
No external security audit, live deployment or authenticated application integration was
performed. The archive has not been pushed to GitHub. See docs/SECURITY_MODEL.md for limits.

## Windows cleanup correction

The supplied Windows Python 3.11 log showed three errors during TemporaryDirectory cleanup.
The three test-owned SQLite connections used transaction context managers without explicit
connection closure. They now use contextlib.closing together with the transaction context,
so commit/rollback happens before close, including on exceptions. The production engine
already explicitly closes its connections. All 25 tests pass after this correction on Linux.
Windows execution still needs confirmation from the user's rerun or GitHub Actions.

## Dashboard development preview

All 44 tests pass on Linux CPython 3.12, including 19 new dashboard/authentication tests.
The HTTP tests start a real loopback server on an ephemeral port and verify authentication,
protected pages, HTML escaping, CSRF and Origin/Host validation, reviewer identity binding,
approval/denial, expiry, logout, rate limiting, input limits and absence of an execution route.
The original v0.1.0 CI passed across Linux/Windows on Python 3.11–3.14. The new dashboard's
Windows and Python matrix results have not yet been verified. This is a development preview,
not a v0.2.0 release or a completed production security review.

## Approval-to-execution runner

The dashboard merge (80c70d6) was confirmed on main; its 44 tests passed on the user's Windows
laptop and its CI matrix passed on Linux/Windows with Python 3.11–3.14.

The new runner was validated with all 57 tests passing on Linux CPython 3.12. This includes
13 runner tests for delayed human approval, denial, expiry, timeout, policy/action changes,
failed storage, single-use consumption, handler failure and a real HTTP dashboard login/
review flow connected to a waiting worker. No automatic reviewer decision occurs in the
shipped runner; test-only reviewer decisions simulate human input. The console handler
accepts only a fixed demo action and produces no external side effects.

## v0.2.0 release preparation

The user verified all 57 tests on Windows after merging PR #2 into main (be755f4).
The dashboard and runner were exercised manually: approval executed the fixed console tool,
denial prevented execution, and audit history recorded the decisions and execution events.
The request-ID fix was verified by a deterministic leading-hyphen regression and successful
Linux/Windows CI runs across Python 3.11–3.14. Release preparation synchronizes package/API
versions to 0.2.0 and includes the changelog in the source distribution. No independent
security audit, public hosting deployment or PyPI publication is claimed.

## v0.3 local toolkit

The local standard-library suite has 76 tests after operational regression additions. The
first v0.3 candidate's 73-test suite passed the complete Linux/Windows Python 3.11–3.14 matrix,
package validation, real Chromium walkthrough and CodeQL in CI run 41843747441 (CodeQL run
41843747458). Later additions cover maintenance CLI flows, schema rollback on injected migration failure
and refusal to modify an unrelated nonempty SQLite database. The final candidate must pass CI before release.

The committed screenshot/video proof was produced by that real automated Chromium run using
only test credentials and sample actions. The recording is slowed five times for readability.
This is not independent security review, external-user validation or evidence of adoption.

A final upgrade-safety regression verifies that an unrelated nonempty SQLite database is
refused without modification, rather than silently acquiring AgentGuard tables.
