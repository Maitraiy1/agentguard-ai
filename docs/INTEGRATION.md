# Trusted-host integration tutorial

AgentGuard sits between an agent's proposed action and a narrow trusted tool adapter. It
is model/provider independent and makes no inference API calls. It does not sandbox Python.

1. Authenticate the requesting principal in your host application. Do not copy a principal
   claim from arbitrary agent JSON and treat it as authenticated.
2. Validate arguments, construct an immutable Action and evaluate policy.
3. For approval actions, create a request and present the exact action in a trusted reviewer UI.
4. After an authenticated decision, call Engine.execute with the same snapshot and request ID.
5. Handle failure without automatic retries, and reconcile external state from audit/system logs.

## Complete local note adapter

Prepare private state/notes directories first. The existing NoteWriter accepts only principal
`demo-agent`, resource `local-notes`, tool `notes.create`, and exactly filename/text parameters.
Its narrow identity check intentionally rejects generic tools. The supplied notes policy has
matching constraints. Both the trusted producer and dashboard must load the same policy/database.

```python
from pathlib import Path
from agentguard import Action, Engine, Policy
from agentguard.core import strict_json
from agentguard.notes import NoteWriter

policy = Policy.from_dict(strict_json(Path("examples/notes-policy.json").read_text()))
engine = Engine(".agentguard/notes.sqlite3", policy, reviewers={"operator"})
writer = NoteWriter(".agentguard/notes")
action = Action("notes.create", "local-notes", "demo-agent", {
    "filename": "approved-note.txt", "text": "A proposed note",
})
request_id = engine.request(action)
# A separate authenticated reviewer process decides. Do not auto-approve here.
# Later, only after review, execute this exact snapshot:
# engine.execute(action, writer, request_id=request_id)
```

`python -m agentguard.notes` implements the bounded wait for that separate decision.
`NoteWriter` is deliberately not a replacement for the engine gate: calling any adapter
directly bypasses approval. Keep adapters and credentials outside the agent's capabilities.

## Designing another adapter

Bind every side-effecting argument in Action.parameters, including destination and version
identifiers. Use narrow schemas and handler validation. Avoid generic shell/SQL/URL adapters
with broad credentials. Revalidate mutable external state inside the handler; approval of a
filename is not approval of content swapped later. Use provider-supported idempotency keys
where possible. Never close over mutable agent dictionaries instead of the approved snapshot.

For async libraries, use a trusted synchronous adapter that completes/awaits the operation.
Passing a coroutine factory directly to Engine.execute is unsupported. Permission is consumed
before the synchronous handler; exactly-once external effects are not guaranteed.
