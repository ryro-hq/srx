# Security controls and rollout evidence

Reviewed against [OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28.html)
on 2026-10-20. Level 1 is the acceptance target, not a certification. Level 2/3
controls below show evidence and gaps individually. Retired BR-01.02 is intentionally
absent. Branch implementation is distinguished from live enforcement and released evidence.

The authoritative readback is [security/github-state.json](../../security/github-state.json).
MFA is active and no members were removed. Existing secret protection and private
reporting remain enabled. New required rules must follow successful workflow rollout;
never require a check that the default branch cannot emit. Keep `success` through
that transition. No bypass or fake independent reviewer is permitted.

| Control | Level | Status | Evidence / remaining work |
| --- | --- | --- | --- |
| OSPS-AC-01.01 | 1 | verified live | Organization MFA enabled after readiness audit; both members retained; [readback](../../security/github-state.json). |
| OSPS-AC-02.01 | 1 | verified live | Organization default repository permission is read; access escalation requires maintainer assignment. |
| OSPS-AC-03.01 | 1 | verified live / migration pending | Existing main rules require PR/checks and prohibit bypass; new verify/DCO/queue settings wait for first successful workflows. |
| OSPS-AC-03.02 | 1 | verified live | Existing main rules prohibit deletion; no bypass actors. |
| OSPS-BR-01.01 | 1 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-01.03 | 1 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-03.01 | 1 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-03.02 | 1 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-07.01 | 1 | verified live | Native secret scanning, non-provider patterns, validity checks and push protection enabled; [policy](../../SECURITY.md). |
| OSPS-DO-01.01 | 1 | implemented | README, authoring/language docs and testing guide describe basic usage; release qualification still pending. |
| OSPS-DO-02.01 | 1 | implemented | CONTRIBUTING links issues for defects and SECURITY for private reports. |
| OSPS-GV-02.01 | 1 | implemented | Repository issues and PRs accept public discussion. |
| OSPS-GV-03.01 | 1 | implemented | [Contribution process](../../CONTRIBUTING.md). |
| OSPS-LE-02.01 | 1 | implemented | Apache-2.0 project LICENSE; Cargo source/license policy in deny.toml. |
| OSPS-LE-02.02 | 1 | pending release evidence | Rust and native-package license policy is separate; license files and SBOM must be verified before publishing. |
| OSPS-LE-03.01 | 1 | implemented | Root LICENSE retained. |
| OSPS-LE-03.02 | 1 | pending release evidence | Release preflight must retain upstream notices/licenses and exact source/patch pins. |
| OSPS-QA-01.01 | 1 | verified live | Public authoritative repository https://github.com/ryro-hq/srx. |
| OSPS-QA-01.02 | 1 | verified live | Git history records authors and time; no history rewrite or published identity removal. |
| OSPS-QA-02.01 | 1 | implemented | Cargo.toml/Cargo.lock; catalog also tracks source releases and qualified combinations. |
| OSPS-QA-04.01 | 1 | implemented | README links core and package catalog and distinguishes runtime ryro-bot. |
| OSPS-QA-05.01 | 1 | implemented in branch | Compiled bootstrap archive removed from catalog; fixtures are generated from source or authenticated pins. |
| OSPS-QA-05.02 | 1 | implemented in branch | Source/configuration/fixtures are reviewable text; logos remain permitted media; no new binaries tracked. |
| OSPS-VM-02.01 | 1 | implemented | [SECURITY.md](../../SECURITY.md) names security maintainer and private reporting channel. |
| OSPS-AC-04.01 | 2 | implemented / live run pending | Least-privilege workflow permissions, read-only untrusted builds and isolated publication; verify first GitHub execution. |
| OSPS-BR-02.01 | 2 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-04.01 | 2 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-05.01 | 2 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-06.01 | 2 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-DO-06.01 | 2 | implemented | [Dependency policy](dependencies.md), README and [testing/build instructions](../testing.md). |
| OSPS-DO-07.01 | 2 | implemented | [Dependency policy](dependencies.md), README and [testing/build instructions](../testing.md). |
| OSPS-GV-01.01 | 2 | implemented | CONTRIBUTING, SECURITY and release/recovery docs define maintainership, access review and contribution requirements. |
| OSPS-GV-01.02 | 2 | implemented | CONTRIBUTING, SECURITY and release/recovery docs define maintainership, access review and contribution requirements. |
| OSPS-GV-03.02 | 2 | implemented | CONTRIBUTING, SECURITY and release/recovery docs define maintainership, access review and contribution requirements. |
| OSPS-LE-01.01 | 2 | rollout pending | Own-author DCO policy documented; CNCF DCO2 App must be confirmed and required before integration. |
| OSPS-QA-03.01 | 2 | verified live / migration pending | Existing success checks required; keep transitional success while verify becomes mandatory. |
| OSPS-QA-06.01 | 2 | implemented / live run pending | Portable tests and required VM qualification; verify includes dependency and workflow policy gates. |
| OSPS-SA-01.01 | 2 | implemented | [Threat model](threat-model.md) identifies actors, boundaries, operations and remaining risks. |
| OSPS-SA-02.01 | 2 | implemented | Language/CLI, authenticated std, typed package contracts, host inspection and transport interfaces documented. |
| OSPS-SA-03.01 | 2 | implemented / human review pending | Threat model plus deterministic parser, type, isolation and negative security tests; no external assessment claimed. |
| OSPS-VM-01.01 | 2 | implemented | Private disclosure policy: 3-working-day acknowledgement target, 7-day triage update, normally 90-day coordination. |
| OSPS-VM-03.01 | 2 | verified live | GitHub private vulnerability reporting enabled in both repositories. |
| OSPS-VM-04.01 | 2 | implemented process | GitHub Security Advisories document affected/fixed identities and mitigations; no advisory fabricated. |
| OSPS-AC-04.02 | 3 | implemented / live run pending | Least-privilege workflow permissions, read-only untrusted builds and isolated publication; verify first GitHub execution. |
| OSPS-BR-01.04 | 3 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-02.02 | 3 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-BR-07.02 | 3 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-DO-03.01 | 3 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-DO-03.02 | 3 | implemented / release evidence pending | [Release/recovery procedure](releases.md), pinned workflows and trusted publication boundary; verify first actual release. |
| OSPS-DO-04.01 | 3 | implemented | [Dependency policy](dependencies.md), README and [testing/build instructions](../testing.md). |
| OSPS-DO-05.01 | 3 | implemented | [Dependency policy](dependencies.md), README and [testing/build instructions](../testing.md). |
| OSPS-GV-04.01 | 3 | implemented | CONTRIBUTING, SECURITY and release/recovery docs define maintainership, access review and contribution requirements. |
| OSPS-QA-02.02 | 3 | pending release evidence | Byte-bound SPDX SBOMs and source/native dependency inventory required before publication. |
| OSPS-QA-04.02 | 3 | rollout pending | Both repositories receive the same security workflow/gate policy; verify remote enforcement after rollout. |
| OSPS-QA-06.02 | 3 | implemented | [Testing guide](../testing.md) distinguishes portable/native/VM checks and weekly schedules. |
| OSPS-QA-06.03 | 3 | implemented | Contribution policy requires behavior/security regression tests for major changes. |
| OSPS-QA-07.01 | 3 | human gap | One write maintainer; no independent approval. Zero approvals temporarily; do not claim level 3 or independent review. |
| OSPS-SA-03.02 | 3 | implemented / human review pending | Threat model covers source, worker, Store, configuration, CI, credential and recovery boundaries. |
| OSPS-VM-04.02 | 3 | implemented policy / no exception claimed | Non-applicability requires reviewed OpenVEX evidence; unknown matching cannot become a safe result. |
| OSPS-VM-05.01 | 3 | implemented | Known exploitable dependencies and license/source violations block; exact expiring exceptions only. |
| OSPS-VM-05.02 | 3 | pending release evidence | SPDX and Grype reports must pass before trusted publication; no release assurance from configuration alone. |
| OSPS-VM-05.03 | 3 | implemented / live run pending | Cargo policy on every PR/merge group; daily independent dependency audit; expiry gate. |
| OSPS-VM-06.01 | 3 | excluded by maintainer | CodeQL excluded by explicit maintainer policy. Dependency and release vulnerability gates remain; no CodeQL coverage claimed. |
| OSPS-VM-06.02 | 3 | excluded by maintainer | CodeQL excluded by explicit maintainer policy; compiler/lints, workflow checks, bounded fuzzing and VM gates remain. |

## OpenSSF Best Practices and Scorecard

No Best Practices badge/project identifier is claimed. The following records are
preparation for an honest badge submission, with maintainer attestation still needed.

| Area | Evidence | Remaining work |
| --- | --- | --- |
| Basics and change control | Public repositories/history, README, contribution guide, PR template, issues and retained identities | Verify new queue/DCO enforcement after rollout |
| Licensing and reporting | LICENSE, scoped Cargo policy, SECURITY and private reporting | Verify distributed package license evidence on first release |
| Quality | Rust/language/configuration/projection tests, formatting, conservative change classification, VM lanes | Retain successful new GitHub/VM runs; no local KVM available in this implementation environment |
| Security | MFA readback, threat model, secret scanning, vulnerability gates, audits and expiring exceptions | Maintainer review, recovery exercise and complete release evidence |
| Release integrity | Immutable-release policy, authenticated artifacts, SPDX/Grype/provenance workflow requirements | Verify actual publication and offline verification; no SLSA level inferred |

The official Scorecard action runs on main and weekly, retains SARIF for 90 days,
and publishes results using OIDC. Its numeric score is diagnostic rather than a merge
gate. A configured action is not a claim that a scan ran or that a score improved.
