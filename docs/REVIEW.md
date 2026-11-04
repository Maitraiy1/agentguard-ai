# Implementation review — 4 November 2026

This is an implementation review performed during AI-assisted development, not an
independent third-party audit or certification. The maintainer manually exercised the v0.2
Windows dashboard and console runner. Automated CI additionally exercises the v0.3 changes.

## Reviewed boundaries and evidence

| Boundary | Controls and regression evidence |
|---|---|
| Action substitution | Immutable canonical snapshots; action/principal/policy mismatch tests |
| Reviewer authorization | Authenticated local dashboard identity; allowlist and self-review checks |
| Browser forms | Real Chromium login/approval/denial/revocation/logout; strict Origin/Host plus CSRF |
| Replay/revocation | SQLite serialized consumption/revocation; terminal-state and concurrent-consumer tests |
| Policy rollback | Durable activation generation; reverting content cannot revive older approvals |
| Upgrade safety | Atomic schema-v1 to v2 migration; injected audit failure rolls migration back |
| Filesystem effects | Narrow note identity/schema; flat filenames; traversal/device/overwrite/symlink tests |
| Storage failure | Permission commits before handler; injected failures verify no premature side effect |
| Operations | Snapshot backup, restore generation invalidation, metadata export and dry-run retention tests |
| Maintenance | Linux/Windows CI, package validation, CodeQL, browser recordings and Dependabot configuration |

## Problems found and corrected during development

- SQLite test context managers were committing transactions without closing connections,
  causing Windows cleanup errors. Connections are explicitly closed.
- A no-referrer header caused browser form Origin to become null. A same-origin policy
  preserves the intended origin check without accepting null/cross-site origins.
- Random IDs could begin with a hyphen and be parsed as CLI flags. A fixed req_ prefix
  preserves entropy and makes new identifiers safe as positional arguments.
- Policy-content hashes alone could revive an approval after rollback. Stored activation
  generations now invalidate old permissions permanently within the same database history.

## Remaining limits and release boundaries

The host, source, policy files, database, adapters and authentication integration are trusted.
An agent with unrestricted same-account execution can bypass the library. Private OS
permissions and agent isolation are prerequisites. Windows filesystem races are not isolated
from another principal already able to modify trusted directory components.

SQLite and external side effects are not one atomic transaction; no exactly-once delivery is
claimed. The note adapter uses exclusive creation to prevent overwrites but does not undo a
partially written new file if the OS/storage fails. Restoring historical databases through
unsupported manual copying may restore historical permission state; use the restore command.

The HTTP service is loopback-only, single-reviewer and lacks production HTTPS, multi-factor
login, distributed rate limiting, external audit integrity, login-event retention and public
service hardening. Session/throttle state resets with restart. Large-scale performance,
independent penetration testing and independent security review have not been completed.
Do not represent a successful CodeQL run as proof that no vulnerabilities exist.
