# Releases and recovery

Core releases use a verified SemVer tag pointing to a commit on main. Catalog
releases use `catalog-<full-commit-sha>` after both pinned userspaces qualify every
matrix entry. Documentation-only changes do not publish catalog releases. Older
published snapshots and source pins are retained without rewriting history.

Build jobs have read permissions. The final trusted publication job downloads the
qualified artifacts, verifies SHA256, attaches license files and SPDX SBOMs,
requires a successful Grype report, and requests GitHub OIDC provenance and SBOM
attestations using the pinned `actions/attest` action. Releases are published as
immutable assets. A workflow file alone is not evidence that a release was qualified.

Before using a downloaded artifact, verify its checksum and expected repository
and workflow identity, for example:

```sh
gh attestation verify FILE --repo ryro-hq/srx \
  --signer-workflow ryro-hq/srx/.github/workflows/release.yml
```

The publisher exports `sha256:DIGEST.jsonl` attestation bundles and a
`trusted_root.jsonl` snapshot and verifies both provenance and SPDX predicates
using those files before publication. To verify a retained artifact offline:

```sh
gh attestation verify FILE --repo REPOSITORY \
  --bundle sha256:DIGEST.jsonl --custom-trusted-root trusted_root.jsonl \
  --signer-workflow REPOSITORY/.github/workflows/WORKFLOW.yml \
  --source-digest EXPECTED_COMMIT --deny-self-hosted-runners
```

Use `--predicate-type https://spdx.dev/Document` to check the SPDX binding as well.
Obtain and retain trust roots through a trusted channel before disconnecting;
shipping roots alongside an untrusted artifact does not itself establish trust.
The artifact digest, issuer and expected signer workflow must all match.

If a release or account is compromised: revoke the relevant App installation/key
and active tokens, restrict publishing, preserve Actions runs/audit logs and hashes,
assess source and Store exposure, publish a GitHub Security Advisory identifying
exact affected/fixed identities, then rebuild and attest a replacement through the
normal queue. Do not silently replace an immutable release or remove retained lock
history. Tell operators explicitly how to identify and remove affected cached or
installed bytes. Never claim that an updater or bot can recall those bytes.

`@fullzer4` currently administers repository access and security reports. Access
escalation needs a documented maintainer decision, MFA readiness and least privilege.
Review access quarterly and after role changes. A second independent write reviewer
and periodic recovery exercises remain explicit human follow-ups.
