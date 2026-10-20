# Rollout evidence

Snapshot: 2026-10-20. This records observed runs and verified live enforcement.

- Organization MFA is enabled; both members remain, with no outside collaborators.
- Immutable releases and Dependabot security updates are enabled in both repositories.
- CNCF DCO2 is installed (App 974774); signed contributions pass its `DCO` check.
- Independent write reviewers: zero. No independent-review or certification claim.
- The catalog updater is prepared and disabled by explicit maintainer choice; no App credentials or PAT are configured. Runtime ryro-bot is outside this migration.

Core [PR #9](https://github.com/ryro-hq/srx/pull/9) merged through the required
rebase queue at `025f32a5c3eec7fc7854f2b950afce625075477f`, retaining the author's
signoff and a single-parent history. Catalog integration is tracked separately in
[PR #4](https://github.com/ryro-hq/srx-pkgs/pull/4).

The [PR run](https://github.com/ryro-hq/srx/actions/runs/39487235286),
[merge-group run](https://github.com/ryro-hq/srx/actions/runs/39489405928) and
[main run](https://github.com/ryro-hq/srx/actions/runs/39491356644) passed every
required gate: GNU/musl static candidates, SPDX/source/license preflight and Grype,
four sanitizer fuzz campaigns, portable tests, both Clippy configurations,
dependency/workflow policy, native VM tests and GNU/musl acceptance VM lanes.
The TLS dependency update passed the refreshed advisory database without adding
advisory exceptions. Later heads must pass their own required workflows.
The [independent audit workflow](https://github.com/ryro-hq/srx/actions/runs/39494435271)
also passed when dispatched on main; its daily schedule is configured separately
from weekly VM qualification.

The [OpenSSF Scorecard run](https://github.com/ryro-hq/srx/actions/runs/39491356604)
passed on main and retained its raw report. CodeQL was removed by explicit
maintainer decision, including its workflows, SARIF gates and proposed exceptions.
No CodeQL coverage or numeric Scorecard improvement is claimed.

After the main workflow succeeded, core ruleset `25046927` was read back with
required `verify` (GitHub Actions App 15368) and `DCO` (CNCF DCO2 App 974774),
rebase-only linear integration, resolved review threads and a one-PR ALLGREEN queue
(360 minutes, no bypass). Deletion and force pushes remain prohibited. DCO2 passed
both the PR and merge-group checks. The initial settings snapshot in
`security/github-state.json` predates this rules transition.

Actual SemVer publication and offline attestation verification remain to be
observed on the first release using the new publishing workflow. No release
assurance, SLSA level, badge or independent review is inferred from CI alone.
The workstation has no KVM; VM evidence above came from GitHub. No K3s cluster was
started.
