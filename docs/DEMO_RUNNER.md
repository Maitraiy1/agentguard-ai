# Full local approval-to-execution demo

The dashboard decides whether an action may run. A separate **trusted runner** performs the
approved action through `Engine.execute`. This demo connects those two pieces with a fixed
console-print tool. It makes no network calls, launches no commands and writes no tool output
files. Its only persistent writes are approval state and audit events in the local database.

## Try it on Windows

From your project folder, install the current source and run tests:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**PowerShell window 1 — dashboard:**

```powershell
.\.venv\Scripts\python.exe -m agentguard.dashboard serve
```

Use your existing password. If this is a fresh installation, run
`python -m agentguard.dashboard init` once first.

**PowerShell window 2 — runner:** Open another PowerShell window in the same project folder.

```powershell
.\.venv\Scripts\python.exe -m agentguard.demo_runner
```

The runner creates a fresh request, displays its ID and exact action, and waits up to five
minutes for your decision. The JSON preview shows the proposed message; it is not tool execution.
The runner never approves its own request. While it waits:

1. Open **http://127.0.0.1:8765**, sign in and refresh **Requests**.
2. Inspect the request matching the ID printed in window 2. The payload says
   `AgentGuard demo: your approval allowed this message to run.`
3. Click **Approve action**.
4. Window 2 prints the message and `Result: executed`, then exits.
5. Refresh **Audit history**: the sequence is `requested`, `approved`,
   `execution_started`, `execution_succeeded`. The request's status becomes **consumed**.

Run the runner command again to create a **new** request, then select **Deny action**.
It exits with `Result: denied`, without starting the tool. No execution events are added
for that denied request. It is normal for a terminal to report exit code 2 for this outcome.

## Behavior and limits

- Approval is consumed exactly once, through the existing engine transaction, before the
  console handler starts. Reusing the request cannot run the handler again.
- The handler accepts only its fixed demo tool/resource/principal/parameter tuple. This
  demo is not a general agent command runner and has no arbitrary tool or shell adapter.
- Denial, expiry, wait timeout and already-consumed state do not start execution. Configuration
  or storage errors fail closed. A failure after consumption is not retried automatically.
- Default request lifetime and wait time are 300 seconds; customize with `--ttl 600`
  (allowed range 1–3600). If no decision arrives, rerun to create a new request.
- Ctrl+C stops waiting. It does not revoke the request or undo any already-started execution.
  Check audit history before retrying. A final audit write can fail after the tool has run;
  the command reports an error and does not automatically retry.
- Both windows must use the **same working folder, database and policy**. If you selected
  another dashboard reviewer during initialization, supply `--reviewer THAT_REVIEWER` to
  the runner. This is trusted service configuration, not authentication input from an agent.
- The runner reloads policy before each state check and again before executing. If its
  content changes, it refuses execution. Restart the dashboard too after policy changes.
  This is still a trusted-host demo, not protection against a compromised process/filesystem
  or atomic policy updates across multiple workers.
- Authentication lives in the dashboard. Do not give an untrusted agent access to the
  database, private credentials, CLI review command, source or unrestricted Python tools.

Global runner options:

```powershell
.\.venv\Scripts\python.exe -m agentguard.demo_runner --db .agentguard\state.sqlite3 --policy examples\policy.json --reviewer operator --ttl 300
```

On Linux/macOS, activate your virtual environment and use `python -m agentguard.demo_runner`.
