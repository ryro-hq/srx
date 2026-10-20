# Security policy

Use [private vulnerability reporting](https://github.com/ryro-hq/srx/security/advisories/new)
to contact the security maintainer, `@fullzer4`. Do not put credentials, exploits
against deployed systems, or private host configurations in public issues.

We aim to acknowledge reports within 3 working days and provide a triage update
within 7 days. We coordinate disclosure with the reporter, normally within 90 days;
actively exploited issues receive priority. These are response targets, not an SLA.
If private reporting is unavailable, request a private contact through the
maintainer's GitHub profile without publishing vulnerability details.

The project is pre-1.0. Security fixes target current `main` and the newest release.
Older releases and catalog snapshots are retained for reproducibility and receive
no automatic backports. An advisory identifies affected and fixed versions,
mitigations, withdrawn artifacts and any end-of-support decision.

Known exploitable dependency vulnerabilities and scanner failures block
integration and releases. Cargo license/source
violations block. Exceptions need exact scope, an owner, justification, evidence
and expiry in `security/exceptions.json`. Release vulnerability false positives
need reviewed OpenVEX evidence; absent or uncertain matching is not evidence of safety.
No blanket ignore or permanent allowlist is accepted.

See the [threat model](docs/security/threat-model.md), [controls and evidence](docs/security/controls.md),
[dependency policy](docs/security/dependencies.md), and [release/recovery procedure](docs/security/releases.md).
The project does not claim OpenSSF certification, a Best Practices badge or a SLSA
level solely because a workflow exists.
