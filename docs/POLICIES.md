# Policy reference

A policy is a JSON object containing exactly `rules`. Each rule requires `tool`, `resource`,
`principal`, `decision`, with optional `parameters`. Matching is exact and case-sensitive.
No wildcard, path normalization, regex or inferred trust is applied. No match means deny.
Deny takes precedence over approval, then allow. Reviewers cannot override a deny.

```json
{
  "rules": [{
    "tool": "notes.create",
    "resource": "local-notes",
    "principal": "demo-agent",
    "decision": "approval",
    "parameters": {
      "filename": {"type": "string", "enum": ["approved-note.txt", "meeting-note.txt"]},
      "text": {"type": "string", "max_length": 2048}
    }
  }]
}
```

When `parameters` is present, every listed key is required and all extra keys are rejected.
This is a deliberately small schema, not a full JSON Schema implementation.

| Constraint | Supported values |
|---|---|
| `type` | `string`, `integer`, `boolean`; strict Python/JSON types, so `true` is not an integer |
| `enum` | 1–100 values, all matching the declared type |
| `max_length` | String character limit, integer 0–65536 |
| `minimum`, `maximum` | Integer bounds, inclusive |

Unknown constraints and malformed types fail configuration loading. Schemas are copied into
immutable snapshots. Constraints from all identity-matching rules intersect: an additional
unconstrained allow rule cannot bypass a stricter rule. Deny rules must be unconditional;
parameter constraints on a deny rule are rejected. If a parameter check fails, the entire
identity match is denied before human approval can be requested.

Existing four-field rules remain supported, but they authorize the entire parameter space
for their matching identity. Use narrow handlers with their own schema validation too.
A `resource` is a label, not an operating-system path containment guarantee.

## Policy activation and permanent invalidation

A database stores one active policy fingerprint and a monotonic generation. Workers with
different policy content cannot create, approve or execute requests, including allow actions.
Changing a file alone does not activate it. Stop workers, back up the database, edit the
policy, then explicitly activate it with trusted local administration:

```powershell
.\.venv\Scripts\python.exe -m agentguard.cli --policy examples\policy.json activate-policy --as operator
```

Every activation increments the generation, even if content is identical. All earlier
approvals remain invalid after reverting to old content; a new request/review is needed.
Restart the dashboard and runners with the same policy and database. Never expose this
administrative CLI or its actor claims to an untrusted agent. Actor flags are not authentication.

## Revocation

An authenticated dashboard reviewer can revoke a pending or approved request. Revocation
and execution consumption use the same serialized SQLite transaction boundary. Revocation
that commits first blocks the tool from starting. It cannot undo a tool that already started,
a consumed request, or a denied request. Revocation is recorded in audit history.
