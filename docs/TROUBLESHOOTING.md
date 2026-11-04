# Troubleshooting

| Symptom | Check and remedy |
|---|---|
| `.venv\\Scripts\\python.exe` not found | Create the virtual environment in this project folder, then install with its Python. |
| Origin/Host rejected | Open the exact printed `http://127.0.0.1:PORT/login` address via the address bar. Do not resubmit an old POST. Use v0.3 and inspect extensions/proxies if they rewrite Origin; do not disable origin checks. |
| Invalid password | Use the password chosen during dashboard init. Do not paste it into issues or logs. |
| Too many attempts | Wait at least 60 seconds; the local throttle limits failed login attempts. |
| Address already in use | Stop the other dashboard or use `serve --port 8766` and open that exact URL. |
| Empty request list | Ensure dashboard and runner use the same working folder, database and policy. The notes tutorial uses notes.sqlite3/notes-policy.json. |
| Request immediately denied | Compare identity and all parameters with the policy; missing/extra fields and invalid enums/ranges are denied. |
| Worker policy is not active | Stop workers; back up; activate the intended policy using trusted local CLI; restart every process consistently. |
| Policy changed / old generation | Create and review a new request. Reverting configuration intentionally does not revive old approvals. |
| Revoked or expired | No execution is permitted. Create a new request if still needed. |
| Existing note file | The adapter never overwrites. Inspect audit/file state and choose another permitted name or move the old test file manually. |
| Notes path rejected | Use a private real directory with no symlink/junction components. Only flat ASCII .txt names are accepted. |
| Permission error | Check private directory permissions and antivirus file locks. Do not solve it by exposing state to all users. |
| Unknown schema | Stop. Use supported versions and a trusted backup; do not lower PRAGMA user_version to bypass validation. |
| Package install error | Confirm Python 3.11+ and a working virtual environment; copy the actual error without credentials. |

A final audit write can fail after a side effect succeeds. Never assume a thrown exception
means the tool did nothing. Inspect the target and audit records before creating another request.
