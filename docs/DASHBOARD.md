# Local reviewer dashboard (v0.2.0 development preview)

This is a password-authenticated, single-reviewer website for your laptop. It uses the
existing Engine API and SQLite state. It can list, inspect, approve and deny requests and
show audit events. It does not execute tools or accept requests from remote agents.

## Windows PowerShell setup

Run these commands from the project folder. If you already have `.venv`, skip its creation.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m agentguard.dashboard init
.\.venv\Scripts\python.exe -m agentguard.dashboard serve --demo
```

`init` asks you to create and confirm a password of at least 12 characters. Password entry
is hidden. It writes a salted scrypt hash, not the password, to `.agentguard/dashboard.json`.
That directory is ignored by Git. `init` refuses to replace existing credentials.

Open **http://127.0.0.1:8765** and sign in with that password. Use this exact address rather
than localhost; the Host check intentionally accepts only the printed address.

1. Click **Inspect** on the demo request.
2. Read the entire action payload, requester, resource and expiry.
3. Click **Approve action** or **Deny action**.
4. Open **Audit history** to see the decision and authenticated reviewer identity.
5. Click **Sign out** when finished. Press Ctrl+C in PowerShell to stop the server.

`--demo` creates one harmless sample approval request with a one-hour expiry on each start.
It uses the supplied sample policy and executes nothing. Once finished with the demo, start
without it: `python -m agentguard.dashboard serve`. Refresh the page to see new requests.

On Linux/macOS activate the virtual environment with `. .venv/bin/activate` and use `python`
in place of `.\.venv\Scripts\python.exe` in the remaining commands.

## Existing agent integration

Both processes must use the same trusted policy file and database path. The dashboard loads
policy at startup; stop and restart it whenever policy changes. Its configured reviewer is
the only permitted reviewer in its Engine instance. Configure that same reviewer allowlist
in the trusted execution service too; approval alone is not tool execution.

In a second PowerShell window, from the project folder:

```powershell
.\.venv\Scripts\python.exe -m agentguard.cli request examples\action.json --ttl 3600
```

Keep passwords and dashboard credentials outside the agent's access. Do not give agents
access to the CLI review command or Python process. The trusted tool adapter still calls
`Engine.execute` with the approved action and request ID, as documented in README.md.

Global options go before the dashboard subcommand:

```powershell
.\.venv\Scripts\python.exe -m agentguard.dashboard --db .agentguard\state.sqlite3 --policy examples\policy.json serve --port 8766
```

## Authentication and operating limits

- Password hashes use scrypt with a fresh 128-bit salt (N=16384, r=8, p=1, 32-byte output).
- Random 256-bit server-side session IDs are kept only in memory. Cookies use HttpOnly,
  SameSite=Strict and Path=/. Sessions expire after 15 minutes idle or 30 minutes total.
- Five failed login attempts block all logins for 60 seconds from the failures' timestamps.
  This is a single-user local throttle, not a distributed abuse prevention system.
- Every POST requires the exact local Origin; decisions and logout also require a random
  session-bound CSRF token. GET requests never approve or deny actions. Browser-supplied
  reviewer identities are rejected. The credential file defines the authenticated reviewer.
- Host validation blocks ordinary DNS rebinding. CSP prevents scripts, frames and external
  resources; all action payloads are HTML-escaped. Responses use no-store caching.
- State changes retain the engine's expiry, policy, reviewer and terminal-state checks.
- Pending and approved requests are displayed as expired or policy-changed when applicable.

The server binds only to **127.0.0.1**, with no option for an external bind address.
This development preview uses Python's standard-library HTTP server over local HTTP.
It is not intended for public hosting, production deployments, proxying, port forwarding,
remote multi-user access or exposure through tunnels. The cookie intentionally lacks
Secure because this loopback preview uses HTTP. Do not reuse a password from another site.

Protect the `.agentguard` directory and backups with private NTFS ACLs on Windows or mode
0700 and umask 077 on POSIX. `init` creates new POSIX directories/files privately, but does
not repair existing permissions or configure Windows ACLs. Anyone with access to these
files or the trusted process can bypass the approval gate. Restart invalidates all sessions
and resets the in-memory login throttle. Rotate credentials only while the server is stopped,
then restart; there is no online password reset or multi-factor login in this preview.

Authenticated pages expose full action parameters. Don't use real secrets in demo actions.
Request display is bounded to the newest 100 rows. Login attempts are not persisted in the
audit database; the audit page shows engine events, not a complete authentication log.
