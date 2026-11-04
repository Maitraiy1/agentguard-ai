# Security model — v0.3 local toolkit

## Trust boundary

The trusted host authenticates agent/reviewer identities, selects policy/database/adapters,
constructs immutable actions and routes every side effect through Engine.execute. Reviewer
strings and CLI `--as` flags are identifiers, not credentials. Administrative commands
(policy activation, backup/restore and retention) must never be exposed as agent capabilities.

An agent that can edit source, policy, database, process memory or invoke the actual adapter
outside the gate can bypass the library. Run untrusted agents with separate OS permissions
and narrow credentials. The local dashboard authenticates one reviewer using a private
salted-scrypt credential file; it is not an authentication service for remote agents.

## Guarantees within that boundary

- Unmatched actions are denied. Identities match exactly. Deny > approval > allow.
- Parameter constraints require exact keys and strict types; failures cannot be bypassed by
  adding an unconstrained rule. The schema subset is documented in POLICIES.md.
- SHA-256 fingerprints bind each approval to the canonical full action, principal and policy.
  Request IDs retain 256 random bits plus a CLI-safe prefix; IDs alone grant no authority.
- Configured reviewers cannot approve their own principal's request. The execution engine rechecks its configured reviewer allowlist. All workers must be
  restarted when reviewer authorization changes. Decisions are terminal; revocation is separately recorded.
- Expiry is checked at review and consumption. Every policy activation advances a durable
  generation, so returning to earlier policy content cannot revive an older approval.
- SQLite BEGIN IMMEDIATE serializes approval consumption, revocation and policy activation.
  Permission and execution_started commit before a trusted synchronous handler runs.
- Revocation that commits before consumption blocks execution; it does not cancel/undo a
  handler already started. Revoked/consumed approvals cannot be used again.
- Schema-v1 migration is additive/transactional. Legacy approval generations are invalidated.
  A failed migration rolls back schema changes. Unsupported newer schemas are refused.
- Audit events contain metadata/digests, not raw parameters or exception messages. Request
  rows and database backups contain full payloads and must remain private.

## Tool and filesystem boundaries

Rules without parameter schemas authorize the entire parameter space for the matching tuple.
Handlers must validate their inputs independently. Resource names are labels, not path
containment checks. Never use broad shell, SQL or arbitrary URL handlers as safe defaults.

The provided NoteWriter accepts one identity and exactly filename/text parameters. Names are
flat ASCII .txt files with no traversal/separators/device names. Exclusive creation refuses
existing files, links and overwrites. On POSIX, directory descriptors and O_NOFOLLOW pin the
final directory and prevent following a target link. Visible symlink/reparse path components
are rejected. On Windows, trusted private NTFS ACLs and trusted parents are required; this
adapter does not isolate races from a malicious actor already able to replace those parents.

All adapters must operate solely on the passed action snapshot, not mutable captured agent
input. Bind versions/content hashes for mutable external resources and recheck them inside
the handler. AgentGuard does not make arbitrary external state changes atomic with approval.

## Crash/retry and operational limits

Execution is synchronous. Use a trusted synchronous adapter that awaits asynchronous APIs;
passing coroutine/generator factories directly is unsupported. A crash or handler failure
burns an approval; no automatic retry occurs. A final audit failure can raise after the side
effect completed. Inspect external state and use idempotency keys before retrying.

Policy activation is privileged, explicit and local. Stop/restart workers consistently.
File changes do not atomically coordinate every process; stale policy hashes fail closed.
Backups are snapshots, not authorization revocation history outside the database. Supported
restore advances generation and invalidates restored approvals; unsupported manual copying
can restore historical permission state. Keep backups private and use OPERATIONS.md.

Audit storage is local/editable, not encrypted or tamper-evident. Export checksums are not
signatures. Retention deletion is a trusted administrative operation with a dry-run default;
export and back up first. Invalid review/auth attempts are not a complete persisted forensic
log. There is no distributed authorization, tenant isolation or exactly-once external delivery.

The local HTTP dashboard uses HttpOnly/SameSite cookies, session-bound CSRF tokens, exact
Origin/Host checks, escaped HTML, a restrictive CSP and no-store responses. Login throttles
and sessions live in memory, expire and reset on restart. HTTP is loopback-only and cookies
therefore intentionally lack Secure. Do not expose it through proxies/tunnels. Public hosting,
HTTPS identity infrastructure, multi-factor login and multi-user roles are separate work.

TTL uses host wall-clock time; synchronize it. Sessions and wait deadlines use monotonic time.
The host clock, filesystem permissions and deployment remain part of the trusted boundary.

See REVIEW.md for implementation review evidence and PROJECT_STATUS.md for work not claimed
as complete. An independent security audit has not been performed.
