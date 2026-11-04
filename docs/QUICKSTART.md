# Five-minute local walkthrough

Requires Python 3.11+ and Git. Run from a trusted private working directory.

```powershell
git clone https://github.com/Maitraiy1/agentguard-ai.git
cd agentguard-ai
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m agentguard.dashboard init
```

Choose a unique password of at least 12 characters. This credential setup is performed once;
do not run init again to start the app. Protect `.agentguard` with your operating system's
private directory permissions; see OPERATIONS.md. Keep it out of the agent's access.

## Real note creation

Window 1, from the project folder:

```powershell
.\.venv\Scripts\python.exe -m agentguard.dashboard --db .agentguard\notes.sqlite3 --policy examples\notes-policy.json serve
```

Window 2, from the **same** project folder:

```powershell
.\.venv\Scripts\python.exe -m agentguard.notes
```

Open **http://127.0.0.1:8765**, sign in, refresh Requests and inspect the new request ID.
Read its entire payload. Click Approve. The runner creates
`.agentguard/notes/approved-note.txt` and audit history records `execution_succeeded`.

The supplied policy permits only `approved-note.txt` and `meeting-note.txt`, and limits text
to 2048 characters. The handler independently rejects traversal, absolute paths, Windows
device names, symlinks and overwrites. Folder setup is trusted initialization; the note file
is created only inside the approved handler after permission consumption.

Run another request and **deny** it:

```powershell
.\.venv\Scripts\python.exe -m agentguard.notes --filename meeting-note.txt --text "This should be blocked."
```

It must report `Result: denied` and must not create the file. To try revocation, create a
request while no runner is waiting (Python API/CLI), approve it, then click **Revoke permission**.
A waiting runner may consume permission immediately after approval, so revocation cannot
reliably beat a runner that already started. The browser test covers revoking before consumption.

## Expected failures

- A filename outside the policy allowlist is denied before requesting approval.
- A reused filename is never overwritten. A later approved write to that filename fails and
  consumes its approval. Inspect the file/audit; choose another permitted filename or move
  the old test file manually before retrying. Do not enable overwrite just to silence an error.
- Revoked/expired/old-generation requests cannot execute; create a new request.
- Stop the first dashboard with Ctrl+C before starting another on the same port.

For Linux/macOS, activate with `. .venv/bin/activate` and use `python` for the remaining commands.
The note adapter is CI-verified on Linux/Windows; private folder permissions are mandatory.
