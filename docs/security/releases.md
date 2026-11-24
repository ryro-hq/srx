# Releases and recovery

Core releases use a verified SemVer tag pointing to a commit on main. Catalog
releases use `catalog-<full-commit-sha>` after both pinned userspaces qualify every
matrix entry. Documentation-only changes do not publish catalog releases. Older
published snapshots and source pins are retained without rewriting history.

## Core candidate and installation

The [v0.1.0 qualification record](release-qualification-v0.1.0.md) lists the
target matrix and names the exact main commit and CI run. For any candidate,
check that the run for that commit includes both target artifacts and the kernel
acceptance jobs. A green run that skipped those jobs is not release evidence.
Review the latest dependency audits before approving the tag; a historical green
run does not override a newer failure. Retain the CI reports and candidate digests
before their Actions retention expires.

Build jobs have read permissions. The final trusted publication job downloads the
qualified artifacts, verifies SHA256, attaches license files and SPDX SBOMs,
requires a successful Grype report, and requests GitHub OIDC provenance and SBOM
attestations using the pinned `actions/attest` action. Releases are published as
immutable assets. A workflow file alone is not evidence that a release was qualified.

Before tagging, review license evidence as well as the current dependency audit.
The release workflow requires successful onboarding from the same main CI run
for both targets and checks both attestations with the network disabled before
publishing.

## Verify before installing

The signed subjects for core are the release `.tar.gz` archives, not Actions
ZIPs, loose binaries or `.sha256` sidecars. The publisher exports
`sha256-DIGEST.jsonl` attestation bundles and a `trusted_root.jsonl` snapshot.
See [Install Syrox](../install.md#download-and-verify) for verified installation
and both provenance and SPDX checks, including
[offline verification](../install.md#verify-an-installation-offline). Obtain
and retain trust roots through a trusted channel before disconnecting; shipping
roots alongside an untrusted artifact does not itself establish trust.

For release qualification, compare the attested archive's internal SPDX file
with the published `.spdx.json` copy. Retain evidence that verification accepted
the original archive and rejected a modified copy against the original bundle.
An offline verifier cannot learn about a subsequent revocation; check security
advisories and refresh trusted roots before importing new material.

## Recovery and revocation

If a release or account is compromised: revoke the relevant App installation/key
and active tokens, restrict publishing, preserve Actions runs/audit logs and hashes,
assess source and Store exposure, publish a GitHub Security Advisory identifying
exact affected/fixed identities, then rebuild and attest a replacement through the
normal queue. Do not silently replace an immutable release or remove retained lock
history. Tell operators explicitly how to identify and remove affected cached or
installed bytes. Never claim that an updater or bot can recall those bytes.

For a non-production exercise, record the affected tag or candidate commit,
target, and SHA-256 of each affected archive/binary. Use disposable caches and
installation prefixes to identify bytes by those hashes, preserve a quarantined
copy, remove the affected copies from active use, and confirm that the candidate
no longer resolves on the test `PATH`. Record who would restrict publishing,
revoke credentials, retain audit evidence, issue the advisory and authorize the
replacement. Use a separate test App or repository if practicing live administrative
steps; a local quarantine or tabletop is not evidence of credential revocation.

`@fullzer4` currently administers repository access and security reports. Access
escalation needs a documented maintainer decision, MFA readiness and least privilege.
Review access quarterly and after role changes. A second independent write reviewer
and periodic recovery exercises remain explicit human follow-ups.
