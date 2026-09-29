# Threat model

TERRACOG reads a Terraform plan, audit events, a ticket export and a world file, and prints a
recommendation with evidence. It never runs `terraform apply`, opens a PR, or calls a cloud API.
Any action it recommends is carried out by a person or by a pipeline that has its own approval step.

## Assets

- The source-of-truth decision for each drifted attribute: a wrong REVERT can re-trigger an incident,
  a wrong CODIFY writes an attacker's or a mistake's change into code where review stops looking.
- The evidence report, used to justify the decision afterwards.

## Trust boundaries

| Input | Trust | Why |
|---|---|---|
| `world.json`: services, dependencies, SLO burn rates, policies, principal directory, controller-owned fields | trusted, code-reviewed | a wrong directory entry turns an attacker into a known engineer; a missing dependency edge shrinks the blast radius |
| Terraform plan JSON | trusted to be what Terraform produced | produced by the pipeline; the parser rejects drift it does not model (deletes) instead of guessing |
| CloudTrail records | integrity trusted, **content is attacker-influenced** | the session name, and so the cited ticket, is chosen by whoever assumes the role |
| Ticket export | trusted for existence, service and status | ticket *content* is free text and is ignored |

## Threats and controls

| Threat | Control |
|---|---|
| An attacker names an IAM user after a trusted role (`user/breakglass-oncall`) | principals are matched by role name from `assumed-role` ARNs only; IAM users are identified by their full ARN tail and are unknown unless listed (`tests/test_terracog.py`) |
| A session name cites a ticket that does not exist, or one for another service | the ticket must exist, match the resource's service and have the right status, or the intent is `unverified` and CODIFY carries a penalty |
| Codifying a live value that violates a high-severity policy | the harm model adds the policy severity to CODIFY; no case in the benchmark codifies a violation of severity >= 7 (`test_never_codifies_a_high_severity_policy_violation`) |
| **Stolen break-glass credentials citing a real open incident** | **not controlled.** The evidence is identical to a real emergency. TERRACOG escalates to a human (it does not codify or hold), but it does not revert. See `NEG-spoofed-breakglass` |
| CloudTrail delivery lag hides the event that explains a hotfix | not controlled: the drift looks unexplained and is escalated (`NEG-audit-log-gap`) |
| Tickets left open after an incident keep a hold alive forever | not controlled: holds need an expiry enforced by whatever applies them (`NEG-stale-incident`) |
| A tampered report is used as evidence | reports record commit SHA, command, seed, Python version and an input hash; regenerate from the commit to verify |
| Supply-chain compromise of CI | no runtime dependencies; actions pinned by commit SHA; workflow token is read-only |

## Out of scope for v0.1

Live cloud reads, applying decisions, PR generation, signed reports, Azure Activity Log input,
and any LLM component. An LLM would at most draft the PR text; it would not own the decision.
