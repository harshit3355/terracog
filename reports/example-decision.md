# TERRACOG drift decisions

_Recommendations only. Nothing was applied. Harm is the model's estimate (see README)._

| Resource | Attribute | IaC | Live | Intent | Action |
|---|---|---|---|---|---|
| `aws_security_group.checkout_app` | `ingress` | `["tcp/8080 10.20.0.0/16"]` | `["tcp/8080 10.20.0.0/16", "tcp/22 0.0.0.0/0"]` | emergency_active | **HUMAN_REVIEW** |

## `aws_security_group.checkout_app.ingress` -> HUMAN_REVIEW

- Intent: **emergency_active** (confidence 0.9): INC-1044 is an open incident on checkout
- Last change: `AuthorizeSecurityGroupIngress` by `breakglass-oncall/bo@INC-1044` at 2026-09-01T11:30:00Z
- Ticket: INC-1044 (incident, open, checkout)
- Service: checkout (tier 1, burn rate 2.5), dependents: edge
- Policies violated by live: no-world-admin-ports, world-ingress-only-web; by IaC: none

| Action | Estimated harm |
|---|---|
| REVERT | 5.7 |
| CODIFY | 11.0 |
| QUARANTINE | 5.6 |
| HUMAN_REVIEW | 3.7 |

Graph edges: aws_security_group.checkout_app -part_of-> checkout; checkout -depended_on_by-> edge; aws_security_group.checkout_app -changed_by-> AuthorizeSecurityGroupIngress@2026-09-01T11:30:00Z; AuthorizeSecurityGroupIngress@2026-09-01T11:30:00Z -principal-> breakglass-oncall; breakglass-oncall -cites-> INC-1044

## Provenance

- commit: `52c5574bd1fdd8f91d0bbc85c333af977ee78637`
- command: `python -m terracog decide --plan build/case/plan.json --events build/case/cloudtrail.json --tickets build/case/tickets.json --world build/case/world.json --report reports/example-decision`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- inputs_sha256: `edf6c722d82dcb27`
- generated_at: `2026-09-29T09:17:10+00:00`
