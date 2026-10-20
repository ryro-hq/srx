# Rollout evidence

Snapshot: 2026-10-20. This records observed runs, separately from final enforcement.

- Organization MFA is enabled; both members remain, with no outside collaborators.
- Immutable releases and Dependabot security updates are enabled in both repositories.
- CNCF DCO2 is installed (App 974774); signed contributions pass its `DCO` check.
- Independent write reviewers: zero. No independent-review or certification claim.
- The catalog updater is prepared and disabled by explicit maintainer choice; no App credentials or PAT are configured. Runtime ryro-bot is outside this migration.

Implementation PRs: [core #9](https://github.com/ryro-hq/srx/pull/9) and
[catalog #4](https://github.com/ryro-hq/srx-pkgs/pull/4).

The [core run at 91bdbe9](https://github.com/ryro-hq/srx/actions/runs/39477237812)
passed GNU/musl static candidate builds, SPDX/source/license preflight and Grype,
all four sanitizer fuzz campaigns, portable tests, both Clippy configurations,
workflow policy and dependency policy. Native and musl acceptance VM lanes passed;
GNU acceptance and the final aggregate must be read from the run. CodeQL was
removed by explicit maintainer decision; its gate, triage and exception records
are not part of the final implementation. Later
heads must pass their own full required workflow; earlier green jobs do not qualify
a changed head.

Catalog VM qualification, final aggregate and trusted publication are still pending.
The portable catalog suite passes locally; the new workflow is being verified in
GitHub. No local KVM is available, and no K3s cluster was started.

Main rules still retain transitional `success`. Transition to required `verify`
and `DCO`, rebase-only linear integration and one-PR ALLGREEN queues (360 minutes,
no bypass) must follow successful default-branch workflow rollout. Release
attestation/offline verification must be checked on actual publication before any
release-assurance claim.
