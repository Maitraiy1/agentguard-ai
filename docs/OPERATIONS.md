# Local operations and v0.3 upgrade

This toolkit is for a trusted single-user local host. Do not expose its HTTP dashboard via
a reverse proxy, tunnel or public interface. Stop workers before changing configuration or
restoring files. All commands below run from the project directory using the virtual environment.

## Upgrade from v0.2

1. Stop the dashboard/runners with Ctrl+C. Record which database and policy each uses.
2. Update source and reinstall (`git pull --ff-only`, then `python -m pip install -e .`).
3. **Before starting any engine**, back up the existing database:

```powershell
.\.venv\Scripts\python.exe -m agentguard.cli backup .agentguard\pre-v0.3.sqlite3
```

The backup command runs before policy loading or engine initialization; it can back up a
schema-v1 database without migrating it. It uses SQLite's snapshot backup API, checks database
integrity and refuses to overwrite an existing destination. For other databases pass `--db`
before `backup`. Choose a new backup name if it already exists.

4. Run the test suite, then start the dashboard. The first Engine open migrates schema v1
   to v2 atomically. Existing passwords, terminal decisions and audit records are retained.
   **All pre-upgrade pending/approved requests are invalidated**; create and review new ones.
5. Keep the backup private. v0.2 engines refuse schema-v2 databases; do not mix versions.

Rollback means stopping all workers, using the old source and original pre-upgrade backup.
Do not reopen an older backup casually: its historical approvals may have been consumed since
that backup was taken. Prefer the v0.3 restore procedure, which invalidates restored approvals.

## Backup and restore

```powershell
.\.venv\Scripts\python.exe -m agentguard.cli backup .agentguard\backup.sqlite3
.\.venv\Scripts\python.exe -m agentguard.cli restore .agentguard\backup.sqlite3 .agentguard\restored.sqlite3 --as operator
```

Restore writes only to a **new** path, validates supported backup tables/schema, migrates if
needed and activates a fresh generation before use. Existing files are never overwritten.
Stop workers and then configure **all** dashboard/runners with the restored database and its
correct policy. The CLI does not swap a running service's database. Credentials are separate:
back up `.agentguard/dashboard.json` privately too; never publish it or its password hash.

## Audit export and retention

```powershell
.\.venv\Scripts\python.exe -m agentguard.cli export-audit .agentguard\audit.jsonl
```

The export is a consistent read snapshot of metadata events only, not action parameters.
Its SHA-256 checksum is printed. Store the export and checksum separately if useful; this is
not a signature or tamper-evident remote log. Export destinations are created privately and
must not exist. Backups contain complete request payloads and require stronger care.

Preview expired/terminal request retention, using a Unix timestamp cutoff:

```powershell
$cutoff = [DateTimeOffset]::UtcNow.AddDays(-30).ToUnixTimeSeconds()
.\.venv\Scripts\python.exe -m agentguard.cli prune --before $cutoff --as operator
```

Nothing is deleted unless `--apply` is supplied. Only requests whose expiry precedes the past
cutoff are eligible; live approvals are retained. Add `--audit-before $cutoff` to also remove
old audit events. Back up/export first, check preview counts, then repeat with `--apply` if
that deletion is intended. A `retention_applied` event records the operation's counts by hash.
These are trusted local administrative commands, not agent tool endpoints.

## Directory permissions

On POSIX set `umask 077` before initialization and restrict `.agentguard` to mode 0700.
New credentials/backups/exports use mode 0600. Existing permissions are not automatically repaired.
On Windows inspect `icacls .agentguard`; use NTFS permissions so only your trusted operator,
service account and required system administrators can read/write it. Do not run an untrusted
agent with the same unrestricted account or grant it access to the source, database or CLI.
Windows path/reparse checks are defense in depth; private ACLs and trusted parents remain essential.

## Monitoring and recovery

Inspect blocked, revoked, execution_failed and migration/policy events. Inspect external state
before retrying any failed execution: permission commits before the handler, while final audit
writes happen after the side effect. There is no exactly-once external delivery guarantee.
Use external idempotency/version checks in real integrations. Login throttles/sessions are in
memory and reset on restart; login attempts are not a durable forensic authentication log.
