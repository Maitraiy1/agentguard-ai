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
