# Security model and operating guidance

## Trusted boundary

The application hosting AgentGuard is trusted. It authenticates the agent and reviewer,
selects the policy and database, constructs the action and calls the real tool handler.
Never accept principal, reviewer, reviewer allowlist, policy or database path directly from
an untrusted request. Reviewer strings are identifiers, not proof of identity.
The CLI is for a trusted local operator. Its `--reviewer`/`--as` flags do not authenticate
anyone. Do not expose it to an agent as a general command tool.

An agent that can edit Python, the policy, the database, process memory or call the real
tool directly can bypass this library. Isolate agents from the trusted host and route every
side-effecting tool through `Engine.execute`. Use OS accounts, narrow credentials and a
sandbox appropriate to the host application. This MVP supplies no HTTP service or login.

## Guarantees within that boundary

* Unmatched actions are denied. Exact tool/resource/principal rules only. Deny overrides
  approval, which overrides allow; rule order does not change the result.
* Approval is bound to a SHA-256 fingerprint of the exact canonical JSON action, including
  principal and all parameters, and the entire policy version. IDs use 256 bits of randomness.
* Only configured reviewers can review, and a principal cannot approve its own request.
  A reviewer removed from the current allowlist cannot authorize execution.
* Requests expire at the expiry instant, not after it. Review cannot resurrect a denied,
  consumed or expired request. Each approved request permits at most one execution start.
* SQLite `BEGIN IMMEDIATE` serializes concurrent consumers. Permission consumption and the
  execution-start event commit before the handler runs. Storage errors prevent handler start.
* Audit records store event metadata and action hashes, not raw parameters or exception text.
  Request records contain the full payload for review, so they may contain sensitive data.

## Limits that matter

Rules do not inspect parameter semantics. An allow rule trusts **all** parameters for that
exact tool/resource/principal tuple. Use narrow purpose-built tool handlers and validate
schemas, destinations, paths, sizes and content before constructing actions. Prefer approval
for side effects. Resource labels are opaque identifiers, not path containment checks.

The trusted handler must operate solely on the passed immutable Action snapshot, validate
its parameters and use the exact resource it names. Do not close over mutable agent input.
If the target state can change after approval (file content, DNS, account ownership), bind
its version/content hash in parameters and verify it again inside the handler. AgentGuard
does not solve external time-of-check/time-of-use problems.

Execution is synchronous. Do not pass async handlers, coroutine factories or lazy generators;
wrap and await them in a trusted synchronous adapter. External side effects and SQLite are
not one atomic transaction. A crash after consumption burns the approval even if no side
effect happened. A handler failure also burns it; inspect the external system and obtain a
new approval before retrying. There is no exactly-once delivery guarantee. If writing the
final audit event fails after the side effect, execute raises even though the effect may
have completed. Use external idempotency keys where supported.

Audit data is local and editable by anyone with database access; it is not a tamper-evident
ledger. Rejected review attempts/invalid approval attempts are exceptions, not stored audit
events in this version. Send application authentication and failure logs to a separate
protected system. Local events have no retention, export integrity, encryption or rotation.

Protect the database directory with mode 0700 and a restrictive umask (077) on POSIX.
On Windows restrict NTFS ACLs to the trusted service/operator. Existing directory permissions
are not repaired by `init`. SQLite files and backups must remain inaccessible to agents.
Use a local filesystem; network filesystem locking semantics are not supported. Use a
separate database per trust domain and do not share writable storage with untrusted users.
Keep policy/reviewer configuration fixed during an execution and deploy policy changes by
restarting trusted workers consistently. All pending approvals become invalid when policy
content changes; reverting to an old policy can make still-unexpired requests valid again.
Use a new database when a policy change must irreversibly revoke all outstanding requests.

TTL uses the host wall clock; keep it synchronized. A clock rollback can extend validity.
There is no distributed authorization, multi-host coordination, revocation endpoint,
rate limiting, tenant isolation, database migration framework or GUI in this MVP.

## Deployment checklist

1. Authenticate identities upstream; never trust agent-supplied reviewer claims.
2. Keep policy, database and tools outside the agent's write/execute permissions.
3. Route every protected tool through execute with narrow schema-validated handlers.
4. Back up the private database, define payload retention, monitor blocked/failed actions.
5. Review the tests and threat model; perform an independent review before high-impact use.
