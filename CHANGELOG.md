# Changelog

## 0.3.0 — 2026-11-04

### Added

- Strict parameter schemas: exact keys, types, enum allowlists and size/integer bounds.
- Create-only note integration with separate constrained policy/database and private output.
- Authenticated reviewer revocation of pending/unconsumed approvals.
- Durable policy activation generations, including permanent invalidation across policy reverts.
- Atomic schema-v2 migration, snapshot backup, safe restore to new paths, metadata audit JSONL
  export/checksum and dry-run retention tooling.
- Real Chromium walkthrough for login, note execution, denial, revocation, audit and logout;
  reproducible screenshots and a slowed recording.
- CodeQL workflow, updated GitHub Actions, Dependabot and issue/PR templates.
- Integration, policy, upgrade/operations, troubleshooting and candid project/review documentation.

### Compatibility

- **Back up before opening an existing database.** Schema v1 migrates to v2 and invalidates
  pre-upgrade pending/approved requests. Passwords, terminal history and audit records remain.
- Old binaries cannot open schema v2. Stop all workers before upgrading.
- Policy changes require explicit trusted activation; old workers with inactive content fail closed.
- Runtime remains dependency-free. Playwright is an optional development/CI extra only.
- This is an early single-user local toolkit; no public hosting, independent audit or adoption
  claim is added. See OPERATIONS.md and REVIEW.md.

## 0.2.0 — 2026-11-04

### Added

- Password-authenticated reviewer dashboard bound to 127.0.0.1.
- Request list, exact action inspection, approve/deny decisions and audit history.
- Salted scrypt password hashes, expiring server-side sessions, login throttling,
  HttpOnly/SameSite cookies, Host/Origin validation, CSRF checks and escaped payloads.
- Trusted demo runner connecting dashboard approval to a fixed console-print tool,
  using the engine's atomic single-use approval gate.
- Runner refusal on denial, expiry, timeout, consumed requests, action mismatch,
  policy changes and storage failures; no automatic approval or execution retry.
- Windows walkthroughs for the dashboard and two-terminal execution demo.
- Real HTTP integration coverage and a total of 57 regression tests.
- CI across Linux and Windows with Python 3.11–3.14, plus package validation.

### Fixed

- Windows temporary database cleanup by explicitly closing test-owned connections.
- Browser form login rejection by using a same-origin referrer policy while retaining
  strict Origin validation and CSRF protection.
- Intermittent CLI failures from random IDs beginning with a hyphen: new IDs use a
  req_ prefix while preserving 256 bits of randomness. Existing request IDs remain valid.

### Compatibility and limits

- Python 3.11 or newer; zero runtime dependencies; MIT licensed.
- No database migration is needed. Existing credentials, requests and audit records remain usable.
- Stop running workers before upgrading, reinstall the package and restart them.
- This is an early local evaluation release, not a public hosting server. The dashboard
  uses loopback HTTP and must not be exposed through tunnels or port forwarding.
- The host application remains trusted and must isolate agents and validate tool inputs.
  Audit logs are local, not tamper-evident; side effects and final audit writes are not atomic.
- No independent security audit or production SLA. No PyPI publication is included.

## 0.1.0 — 2026-11-04

Initial MVP: default-deny exact-match policies, immutable action snapshots, expiring
single-use approvals, reviewer allowlists, SQLite audit events, Python API and CLI,
safe examples, MIT license, contributing/security documentation and CI.
