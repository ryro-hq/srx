# Threat model

The trusted boundary contains the checked compiler/engine, authenticated std,
explicit project lock, worker admission policy and reviewed release workflow.
Actors include package authors, upstream publishers, project consumers, local
users, GitHub contributors, maintainers and compromised build/dependency services.

| Surface | Adversary input and mitigation | Remaining verification |
| --- | --- | --- |
| Language/configuration | Untrusted srx, YAML and TOML; bounded parsing/evaluation, typed fields, explicit defaults, immutable edits and authenticated text assets | Fuzzing supplements deterministic regression cases |
| Sources | Malicious archive, redirects, replaced upstream bytes; exact digests/signatures, bounded archive inventory and explicit origin grants | Pins prove bytes, not benign behavior |
| Worker and host | Arbitrary build programs; typed paths, selected inputs, confinement, descriptor admission, deadlines and cancellation | Full Linux kernel/VM lanes qualify isolation; host interface observation is not permission proof |
| Store and transport | Corrupt blobs, bundles and receipts; content addressing, verified imports, authenticated closure and offline execution checks | Existing cached bytes require explicit operator withdrawal/removal |
| Configuration | Unknown external fields and host secrets; typed edits preserve comments, explicit file writes and secret references | Avoid logging concrete credentials in plans or evidence |
| CI and release | Malicious PR, artifact substitution or token theft; read-only build jobs, exact source revision, verified artifacts, final OIDC publication, byte-bound SBOM/provenance | Independent human review remains a gap with one write maintainer |
| Recovery | Compromised account, signing workflow or release; MFA, no bypass, revoke credentials, preserve evidence, publish advisory and verify replacement bytes | Automation cannot revoke bytes already installed or cached by users |

K3s examples prepare packages and configuration. They do not provision machines,
start privileged clusters or promise RKE2 compatibility. The runtime ryro-bot is
outside this change; an updater App only opens normal catalog PRs.
