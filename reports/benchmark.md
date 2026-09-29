# TERRACOG benchmark: which source of truth should win?

_SYNTHETIC cases with AUTHOR-ASSIGNED labels and harm values. Every number below was produced by the command in the provenance section._

- 56 drift cases (4 of them negative cases, written in advance to exercise known blind spots), rendered into Terraform plan JSON, CloudTrail records and ticket exports.
- Correct-action distribution: REVERT 18, CODIFY 17, QUARANTINE 12, HUMAN_REVIEW 9.
- CDR = harm of the chosen action minus the lowest harm available for that case (0-10 rubric in `fixtures/cases.json`). Lower is better.

## All cases

| Method | Correct | Mean CDR | Total CDR | Wrong auto-remediation | Regret >= 5 | Human reviews |
|---|---|---|---|---|---|---|
| Always revert to Terraform | 18/56 | 2.75 | 154 | 38 | 11 | 0 |
| Always codify live state | 17/56 | 3.6786 | 206 | 39 | 18 | 0 |
| Always page a human | 9/56 | 1.625 | 91 | 0 | 5 | 56 |
| Severity-only triage (tfdrift-style) | 17/56 | 2.125 | 119 | 24 | 8 | 15 |
| Provenance rules, no counterfactual (ablation) | 41/56 | 0.8393 | 47 | 11 | 4 | 2 |
| Counterfactual, provenance ignored (ablation) | 16/56 | 1.375 | 77 | 21 | 4 | 21 |
| Counterfactual, no dependency blast radius (ablation) | 42/56 | 0.4464 | 25 | 11 | 1 | 4 |
| **TERRACOG: provenance + counterfactual harm** | 39/56 | 0.5893 | 33 | 11 | 2 | 7 |

Wrong auto-remediation = the method chose REVERT or CODIFY and that was not the correct action.

## Excluding the 4 negative cases / negative cases only

| Method | Mean CDR (non-negative) | Correct (non-negative) | Mean CDR (negative) | Correct (negative) |
|---|---|---|---|---|
| Always revert to Terraform | 2.7115 | 16/52 | 3.25 | 2/4 |
| Always codify live state | 3.6538 | 16/52 | 4.0 | 1/4 |
| Always page a human | 1.5769 | 9/52 | 2.25 | 0/4 |
| Severity-only triage (tfdrift-style) | 2.25 | 15/52 | 0.5 | 2/4 |
| Provenance rules, no counterfactual (ablation) | 0.6538 | 40/52 | 3.25 | 1/4 |
| Counterfactual, provenance ignored (ablation) | 1.3077 | 16/52 | 2.25 | 0/4 |
| Counterfactual, no dependency blast radius (ablation) | 0.4231 | 40/52 | 0.75 | 2/4 |
| **TERRACOG: provenance + counterfactual harm** | 0.4423 | 39/52 | 2.5 | 0/4 |

## Paired bootstrap: mean CDR(method) - mean CDR(TERRACOG), 95% interval, seed 7

| Method | Difference | 95% interval |
|---|---|---|
| Always revert to Terraform | 2.1607 | [1.2143, 3.125] |
| Always codify live state | 3.0893 | [2.1429, 4.0714] |
| Always page a human | 1.0357 | [0.5893, 1.5] |
| Severity-only triage (tfdrift-style) | 1.5357 | [0.7143, 2.3929] |
| Provenance rules, no counterfactual (ablation) | 0.25 | [-0.1964, 0.7679] |
| Counterfactual, provenance ignored (ablation) | 0.7857 | [0.4464, 1.2321] |
| Counterfactual, no dependency blast radius (ablation) | -0.1429 | [-0.375, 0.0] |

The interval resamples these author-written cases; it says how stable the ranking is on this set, not how the methods would do on real drift.

## Mean CDR by category

| Category | always revert | always codify | always human review | severity only | intent rules no counterfactual | counterfactual no intent | counterfactual no blast radius | terracog |
|---|---|---|---|---|---|---|---|---|
| approved_uncodified | 1.75 | 1.5 | 1.25 | 1.5 | 0.0 | 1.25 | 0.0 | 0.0 |
| config_drift | 1.0 | 2.0 | 1.3333 | 1.0 | 0.3333 | 1.0 | 1.0 | 1.0 |
| controller_managed | 4.2 | 4.0 | 1.8 | 3.2 | 0.0 | 3.6 | 0.0 | 0.0 |
| dns_fix | 3.8 | 3.2 | 1.8 | 3.8 | 0.6 | 1.8 | 1.4 | 1.4 |
| emergency_hotfix | 9.5 | 2.1667 | 1.0 | 6.6667 | 0.0 | 1.0 | 0.0 | 0.0 |
| emergency_resolved | 2.0 | 2.5 | 1.25 | 1.0 | 2.5 | 0.75 | 0.5 | 0.5 |
| iam_widening | 1.0 | 5.3333 | 1.0 | 1.0 | 2.6667 | 1.0 | 1.0 | 1.0 |
| negative | 3.25 | 4.0 | 2.25 | 0.5 | 3.25 | 2.25 | 0.75 | 2.5 |
| public_exposure | 0.4 | 8.4 | 3.4 | 0.4 | 0.8 | 0.4 | 0.4 | 0.4 |
| replica_change | 0.8 | 4.8 | 2.0 | 1.0 | 0.0 | 0.8 | 0.0 | 0.2 |
| security_group_mutation | 1.5714 | 4.1429 | 1.5714 | 1.5714 | 0.8571 | 1.2857 | 0.1429 | 0.1429 |
| tag_drift | 1.2 | 1.6 | 0.6 | 1.6 | 0.4 | 1.2 | 0.8 | 0.8 |

## TERRACOG per case

| Case | Inferred intent (confidence) | Correct | Chosen | CDR | Severity-only chose |
|---|---|---|---|---|---|
| `hotfix-checkout-min-size` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | HUMAN_REVIEW |
| `hotfix-payments-task-count` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | HUMAN_REVIEW |
| `hotfix-dns-failover` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `hotfix-internal-port` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `hotfix-db-upsize` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `hotfix-session-cache-replicas` | emergency_active (0.75) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `resolved-capacity-keep` | emergency_resolved (0.8) | CODIFY | CODIFY | 0 | HUMAN_REVIEW |
| `resolved-debug-port-left-open` | emergency_resolved (0.8) | REVERT | REVERT | 0 | REVERT |
| `resolved-dns-still-failed-over` | emergency_resolved (0.8) | HUMAN_REVIEW | CODIFY | 2 | REVERT |
| `resolved-lambda-timeout` | emergency_resolved (0.8) | CODIFY | CODIFY | 0 | HUMAN_REVIEW |
| `autoscaler-desired-capacity` | controller (0.95) | QUARANTINE | QUARANTINE | 0 | HUMAN_REVIEW |
| `appautoscaling-task-count` | controller (0.95) | QUARANTINE | QUARANTINE | 0 | HUMAN_REVIEW |
| `rds-auto-minor-upgrade` | controller (0.95) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `autoscaler-scale-in-night` | controller (0.95) | QUARANTINE | QUARANTINE | 0 | HUMAN_REVIEW |
| `human-zeroes-controller-field` | ad_hoc (0.7) | REVERT | REVERT | 0 | HUMAN_REVIEW |
| `tag-add-cost-center` | ad_hoc (0.7) | CODIFY | REVERT | 1 | CODIFY |
| `tag-owner-removed` | ad_hoc (0.7) | REVERT | REVERT | 0 | CODIFY |
| `tag-by-unknown-principal` | suspicious (0.8) | HUMAN_REVIEW | REVERT | 1 | CODIFY |
| `tag-owner-transfer-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | CODIFY |
| `tag-backup-no-event` | unknown (0.0) | HUMAN_REVIEW | REVERT | 2 | CODIFY |
| `sg-ssh-world-developer` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `sg-postgres-world-unknown` | suspicious (0.8) | REVERT | REVERT | 0 | REVERT |
| `sg-internal-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `sg-tighten-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `sg-rule-removed-adhoc` | ad_hoc (0.7) | HUMAN_REVIEW | REVERT | 1 | REVERT |
| `sg-http-world-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `sg-ssh-world-during-incident` | emergency_active (0.9) | HUMAN_REVIEW | HUMAN_REVIEW | 0 | REVERT |
| `s3-public-developer` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `rds-public-unverified-ticket` | unverified (0.8) | REVERT | REVERT | 0 | REVERT |
| `s3-public-approved-website` | approved_change (0.85) | HUMAN_REVIEW | REVERT | 2 | REVERT |
| `rds-public-unknown-principal` | suspicious (0.8) | REVERT | REVERT | 0 | REVERT |
| `ebs-encryption-disabled` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `cache-replicas-down-adhoc` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `task-count-cut-approved` | approved_change (0.85) | CODIFY | HUMAN_REVIEW | 1 | HUMAN_REVIEW |
| `rds-multi-az-off-adhoc` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `asg-min-down-adhoc` | ad_hoc (0.7) | REVERT | REVERT | 0 | HUMAN_REVIEW |
| `reporting-db-downsize-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `dns-drain-primary-incident` | emergency_active (0.9) | QUARANTINE | QUARANTINE | 0 | REVERT |
| `dns-ttl-lowered` | ad_hoc (0.7) | CODIFY | REVERT | 1 | HUMAN_REVIEW |
| `dns-hijack-unknown` | suspicious (0.8) | REVERT | HUMAN_REVIEW | 6 | REVERT |
| `dns-migration-approved` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `dns-repoint-adhoc` | ad_hoc (0.7) | HUMAN_REVIEW | HUMAN_REVIEW | 0 | REVERT |
| `approved-db-upsize` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `approved-lambda-memory` | approved_change (0.85) | CODIFY | CODIFY | 0 | HUMAN_REVIEW |
| `approved-backup-retention` | approved_change (0.85) | CODIFY | CODIFY | 0 | REVERT |
| `ticket-for-other-service` | unverified (0.8) | REVERT | REVERT | 0 | REVERT |
| `iam-wildcard-adhoc` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `iam-wildcard-approved` | approved_change (0.85) | HUMAN_REVIEW | REVERT | 1 | REVERT |
| `iam-narrowed-adhoc` | ad_hoc (0.7) | HUMAN_REVIEW | REVERT | 2 | REVERT |
| `tls-policy-downgrade` | ad_hoc (0.7) | REVERT | REVERT | 0 | REVERT |
| `lambda-timeout-adhoc` | ad_hoc (0.7) | CODIFY | REVERT | 1 | HUMAN_REVIEW |
| `deletion-protection-off-decommission` | approved_change (0.85) | CODIFY | REVERT | 2 | REVERT |
| `NEG-spoofed-breakglass` (negative) | emergency_active (0.9) | REVERT | HUMAN_REVIEW | 5 | REVERT |
| `NEG-audit-log-gap` (negative) | unknown (0.0) | QUARANTINE | HUMAN_REVIEW | 1 | HUMAN_REVIEW |
| `NEG-stale-incident` (negative) | emergency_active (0.9) | CODIFY | QUARANTINE | 2 | HUMAN_REVIEW |
| `NEG-cost-not-modelled` (negative) | ad_hoc (0.7) | REVERT | HUMAN_REVIEW | 2 | REVERT |

## Where TERRACOG is wrong

- `resolved-dns-still-failed-over`: chose CODIFY, correct HUMAN_REVIEW (CDR 2); evidence: INC-3002 is a resolved incident on edge.
- `tag-add-cost-center`: chose REVERT, correct CODIFY (CDR 1); evidence: developer changed it without citing a ticket.
- `tag-by-unknown-principal`: chose REVERT, correct HUMAN_REVIEW (CDR 1); evidence: principal user/svc-legacy is not in the directory.
- `tag-backup-no-event`: chose REVERT, correct HUMAN_REVIEW (CDR 2); evidence: no audit event touches this attribute.
- `sg-rule-removed-adhoc`: chose REVERT, correct HUMAN_REVIEW (CDR 1); evidence: developer changed it without citing a ticket.
- `s3-public-approved-website`: chose REVERT, correct HUMAN_REVIEW (CDR 2); evidence: CHG-7005 is an approved change for edge.
- `task-count-cut-approved`: chose HUMAN_REVIEW, correct CODIFY (CDR 1); evidence: CHG-7006 is an approved change for catalog.
- `dns-ttl-lowered`: chose REVERT, correct CODIFY (CDR 1); evidence: platform-engineer changed it without citing a ticket.
- `dns-hijack-unknown`: chose HUMAN_REVIEW, correct REVERT (CDR 6); evidence: principal user/svc-legacy is not in the directory.
- `iam-wildcard-approved`: chose REVERT, correct HUMAN_REVIEW (CDR 1); evidence: CHG-7013 is an approved change for checkout.
- `iam-narrowed-adhoc`: chose REVERT, correct HUMAN_REVIEW (CDR 2); evidence: security-engineer changed it without citing a ticket.
- `lambda-timeout-adhoc`: chose REVERT, correct CODIFY (CDR 1); evidence: developer changed it without citing a ticket.
- `deletion-protection-off-decommission`: chose REVERT, correct CODIFY (CDR 2); evidence: CHG-7014 is an approved change for reporting.
- `NEG-spoofed-breakglass`: chose HUMAN_REVIEW, correct REVERT (CDR 5); evidence: INC-2004 is an open incident on payments.
- `NEG-audit-log-gap`: chose HUMAN_REVIEW, correct QUARANTINE (CDR 1); evidence: no audit event touches this attribute.
- `NEG-stale-incident`: chose QUARANTINE, correct CODIFY (CDR 2); evidence: INC-1001 is an open incident on checkout.
- `NEG-cost-not-modelled`: chose HUMAN_REVIEW, correct REVERT (CDR 2); evidence: developer changed it without citing a ticket.

## Evidence coverage

- Drifts with a linked audit event: 54/56
- Drifts whose provenance was verified (controller-owned field, or a ticket that exists, is for the same service and is open/resolved/approved): 31/56

## Provenance

- commit: `52c5574bd1fdd8f91d0bbc85c333af977ee78637`
- command: `python -m terracog bench --out reports`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- inputs_sha256: `6ae75e7304a939d5`
- generated_at: `2026-09-29T09:16:54+00:00`
- seed: `7`
- fixtures: `fixtures/world.json + fixtures/cases.json`
