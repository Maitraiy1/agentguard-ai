# Security policy

Version 0.2.x is an early MVP, without an independent security audit or production SLA.
Report suspected vulnerabilities using the repository's **Security → Report a vulnerability**
feature. Private vulnerability reporting is enabled for this repository.
If that feature is unavailable, request a private contact route without publishing exploit
steps, secrets or affected customer data. No security email address is configured yet.

Read [the threat model](docs/SECURITY_MODEL.md) before deployment. This is a trusted-host
policy library, not a sandbox, authentication server or defense against a compromised host.
The current 0.2.x line receives fixes; users of 0.1.x should upgrade. Security changes require regression coverage.
