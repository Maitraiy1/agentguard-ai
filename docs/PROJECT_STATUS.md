# Project status

AgentGuard AI is an early-stage, single-maintainer, AI-assisted open-source project started
in November 2026. It has real source code, regression tests, CI, release history and local
manual validation. It does not claim a long maintenance history, external customers,
independent security approval or broad ecosystem adoption.

## Delivered local scope

Default-deny policies, strict parameter constraints, human review, expiring single-use
approvals, revocation, durable policy generations, a password-authenticated local dashboard,
a create-only note integration, migration/backup/restore/export/retention tooling,
Windows documentation, cross-platform tests and a recorded real-browser walkthrough.

## Evidence

- CI: https://github.com/Maitraiy1/agentguard-ai/actions/workflows/ci.yml
- CodeQL: https://github.com/Maitraiy1/agentguard-ai/actions/workflows/security.yml
- Reviewed changes: https://github.com/Maitraiy1/agentguard-ai/pulls?q=is%3Apr
- Releases: https://github.com/Maitraiy1/agentguard-ai/releases
- Reproducible walkthrough: browser_tests/test_browser.py and docs/media/walkthrough.mp4
- Limitations and development review: docs/SECURITY_MODEL.md and docs/REVIEW.md

## Work that requires more time or external participation

Independent security review, real-user feedback, usage/adoption evidence and long-term
maintenance cannot be established by adding commits in one session. A publicly hosted
multi-user service would need a separate architecture/security project. External tools,
MCP/model integrations and additional policy types should be driven by actual use cases.

Contributors are welcome to reproduce bugs, improve accessibility and documentation, add
platform-specific security tests and review the threat model. Open real, scoped issues with
reproduction steps; do not manufacture engagement, stars or claims of users.
