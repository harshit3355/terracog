"""Benchmark: Counterfactual Drift Regret of TERRACOG vs baselines and ablations on labelled synthetic cases.

CDR(case, method) = harm[chosen action] - min(harm), with harm author-assigned per action per case.
"""
from __future__ import annotations

import random
from collections import defaultdict

from .engine import ACTIONS, analyse, parse_cloudtrail, parse_plan, parse_tickets
from .scenarios import render

# tfdrift-style severity: by resource type and attribute only, never by value or provenance.
CRITICAL = {"aws_security_group.ingress", "aws_iam_role_policy.policy", "aws_db_instance.publicly_accessible",
            "aws_ebs_encryption_by_default.enabled", "aws_lb_listener.ssl_policy",
            "aws_s3_bucket_public_access_block.block_public_policy",
            "aws_s3_bucket_public_access_block.restrict_public_buckets"}
HIGH = {"aws_db_instance.instance_class", "aws_db_instance.multi_az", "aws_db_instance.engine_version",
        "aws_db_instance.deletion_protection", "aws_db_instance.backup_retention_period",
        "aws_elasticache_replication_group.num_cache_clusters", "aws_route53_record.records",
        "aws_route53_record.weight"}


def severity(rtype: str, attr: str) -> str:
    key = f"{rtype}.{attr}"
    return "critical" if key in CRITICAL else "high" if key in HIGH else "low" if attr == "tags" else "medium"


SEVERITY_ACTION = {"critical": "REVERT", "high": "REVERT", "medium": "HUMAN_REVIEW", "low": "CODIFY"}
# The intent component alone, as a runbook would encode it: no security, SLO or blast-radius reasoning.
INTENT_RULES = {"emergency_active": "QUARANTINE", "controller": "QUARANTINE", "emergency_resolved": "CODIFY",
                "approved_change": "CODIFY", "ad_hoc": "REVERT", "unverified": "REVERT", "suspicious": "REVERT",
                "unknown": "HUMAN_REVIEW"}

METHODS = ("always_revert", "always_codify", "always_human_review", "severity_only", "intent_rules_no_counterfactual",
           "counterfactual_no_intent", "counterfactual_no_blast_radius", "terracog")
LABELS = {"always_revert": "Always revert to Terraform",
          "always_codify": "Always codify live state",
          "always_human_review": "Always page a human",
          "severity_only": "Severity-only triage (tfdrift-style)",
          "intent_rules_no_counterfactual": "Provenance rules, no counterfactual (ablation)",
          "counterfactual_no_intent": "Counterfactual, provenance ignored (ablation)",
          "counterfactual_no_blast_radius": "Counterfactual, no dependency blast radius (ablation)",
          "terracog": "**TERRACOG: provenance + counterfactual harm**"}
AUTO = {"REVERT", "CODIFY"}


def run_case(c: dict, world_raw: dict) -> dict:
    plan, trail, tix, world = render(c, world_raw)
    events, tickets = parse_cloudtrail(trail), parse_tickets(tix)
    (d,) = parse_plan(plan)
    full = analyse(d, events, tickets, world)
    e = full["evidence"]
    choice = {"always_revert": "REVERT", "always_codify": "CODIFY", "always_human_review": "HUMAN_REVIEW",
              "severity_only": SEVERITY_ACTION[severity(d.type, d.attr)],
              "intent_rules_no_counterfactual": INTENT_RULES[e["intent"]],
              "counterfactual_no_intent": analyse(d, events, tickets, world, use_intent=False)["action"],
              "counterfactual_no_blast_radius": analyse(d, events, tickets, world, use_blast=False)["action"],
              "terracog": full["action"]}
    best = min(c["harm"].values())
    return {"id": c["id"], "category": c["category"], "negative": bool(c.get("negative")), "label": c["label"],
            "harm": c["harm"], "intent": e["intent"], "confidence": e["confidence"], "reason": e["reason"],
            "estimated_harm": full["harm"], "event_linked": e["event"] is not None,
            "provenance_verified": e["intent"] in ("controller", "emergency_active", "emergency_resolved",
                                                   "approved_change"),
            "choice": choice, "regret": {m: c["harm"][a] - best for m, a in choice.items()}}


def _summary(rows: list[dict]) -> dict:
    n = len(rows)
    out = {}
    for m in METHODS:
        reg = [r["regret"][m] for r in rows]
        out[m] = {"n": n, "correct": sum(r["choice"][m] == r["label"] for r in rows),
                  "accuracy": round(sum(r["choice"][m] == r["label"] for r in rows) / n, 4),
                  "mean_cdr": round(sum(reg) / n, 4), "total_cdr": sum(reg),
                  "false_auto_remediation": sum(r["choice"][m] in AUTO and r["choice"][m] != r["label"] for r in rows),
                  "severe_regret_cases": sum(x >= 5 for x in reg),
                  "human_reviews": sum(r["choice"][m] == "HUMAN_REVIEW" for r in rows)}
    return out


def _bootstrap(rows: list[dict], rng: random.Random, n: int = 2000) -> dict:
    """95% interval of mean CDR(method) - mean CDR(terracog), resampling cases with replacement."""
    out = {}
    for m in METHODS:
        if m == "terracog":
            continue
        diffs = [r["regret"][m] - r["regret"]["terracog"] for r in rows]
        means = sorted(sum(rng.choice(diffs) for _ in diffs) / len(diffs) for _ in range(n))
        out[m] = {"mean_diff": round(sum(diffs) / len(diffs), 4),
                  "ci95": [round(means[int(0.025 * n)], 4), round(means[int(0.975 * n) - 1], 4)]}
    return out


def bench(cases: list[dict], world_raw: dict, seed: int) -> dict:
    rows = [run_case(c, world_raw) for c in cases]
    cats = defaultdict(list)
    for r in rows:
        cats[r["category"]].append(r)
    return {"seed": seed, "cases": len(rows), "negative_cases": sum(r["negative"] for r in rows),
            "label_distribution": {a: sum(r["label"] == a for r in rows) for a in ACTIONS},
            "summary": _summary(rows),
            "summary_excluding_negative": _summary([r for r in rows if not r["negative"]]),
            "summary_negative_only": _summary([r for r in rows if r["negative"]]),
            "bootstrap_vs_terracog": _bootstrap(rows, random.Random(seed)),
            "by_category": {k: {m: _summary(v)[m]["mean_cdr"] for m in METHODS} for k, v in sorted(cats.items())},
            "evidence": {"event_linked": sum(r["event_linked"] for r in rows),
                         "provenance_verified": sum(r["provenance_verified"] for r in rows)},
            "cases_detail": rows}


def markdown(rep: dict) -> str:
    s, n = rep["summary"], rep["cases"]
    L = ["# TERRACOG benchmark: which source of truth should win?", "",
         "_SYNTHETIC cases with AUTHOR-ASSIGNED labels and harm values. Every number below was produced by the "
         "command in the provenance section._", "",
         f"- {n} drift cases ({rep['negative_cases']} of them negative cases, written in advance to exercise known "
         f"blind spots), rendered into Terraform plan JSON, CloudTrail records and ticket exports.",
         "- Correct-action distribution: " + ", ".join(f"{a} {k}" for a, k in rep["label_distribution"].items()) + ".",
         "- CDR = harm of the chosen action minus the lowest harm available for that case (0-10 rubric in "
         "`fixtures/cases.json`). Lower is better.", "",
         "## All cases", "",
         "| Method | Correct | Mean CDR | Total CDR | Wrong auto-remediation | Regret >= 5 | Human reviews |",
         "|---|---|---|---|---|---|---|"]
    for m in METHODS:
        x = s[m]
        L.append(f"| {LABELS[m]} | {x['correct']}/{x['n']} | {x['mean_cdr']} | {x['total_cdr']} | "
                 f"{x['false_auto_remediation']} | {x['severe_regret_cases']} | {x['human_reviews']} |")
    L += ["", "Wrong auto-remediation = the method chose REVERT or CODIFY and that was not the correct action.", "",
          f"## Excluding the {rep['negative_cases']} negative cases / negative cases only", "",
          "| Method | Mean CDR (non-negative) | Correct (non-negative) | Mean CDR (negative) | Correct (negative) |",
          "|---|---|---|---|---|"]
    for m in METHODS:
        a, b = rep["summary_excluding_negative"][m], rep["summary_negative_only"][m]
        L.append(f"| {LABELS[m]} | {a['mean_cdr']} | {a['correct']}/{a['n']} | {b['mean_cdr']} | {b['correct']}/{b['n']} |")
    L += ["", f"## Paired bootstrap: mean CDR(method) - mean CDR(TERRACOG), 95% interval, seed {rep['seed']}", "",
          "| Method | Difference | 95% interval |", "|---|---|---|"]
    for m, x in rep["bootstrap_vs_terracog"].items():
        L.append(f"| {LABELS[m]} | {x['mean_diff']} | [{x['ci95'][0]}, {x['ci95'][1]}] |")
    L += ["", "The interval resamples these author-written cases; it says how stable the ranking is on this set, "
              "not how the methods would do on real drift.", "",
          "## Mean CDR by category", "",
          "| Category | " + " | ".join(m.replace("_", " ") for m in METHODS) + " |",
          "|---|" + "---|" * len(METHODS)]
    for k, v in rep["by_category"].items():
        L.append(f"| {k} | " + " | ".join(str(v[m]) for m in METHODS) + " |")
    L += ["", "## TERRACOG per case", "",
          "| Case | Inferred intent (confidence) | Correct | Chosen | CDR | Severity-only chose |", "|---|---|---|---|---|---|"]
    for r in rep["cases_detail"]:
        mark = " (negative)" if r["negative"] else ""
        L.append(f"| `{r['id']}`{mark} | {r['intent']} ({r['confidence']}) | {r['label']} | {r['choice']['terracog']} | "
                 f"{r['regret']['terracog']} | {r['choice']['severity_only']} |")
    wrong = [r for r in rep["cases_detail"] if r["regret"]["terracog"] > 0]
    L += ["", "## Where TERRACOG is wrong", ""]
    L += [f"- `{r['id']}`: chose {r['choice']['terracog']}, correct {r['label']} (CDR {r['regret']['terracog']}); "
          f"evidence: {r['reason']}." for r in wrong] or ["- nowhere"]
    ev = rep["evidence"]
    L += ["", "## Evidence coverage", "",
          f"- Drifts with a linked audit event: {ev['event_linked']}/{n}",
          f"- Drifts whose provenance was verified (controller-owned field, or a ticket that exists, is for the same "
          f"service and is open/resolved/approved): {ev['provenance_verified']}/{n}", "",
          "## Provenance", "", *(f"- {k}: `{v}`" for k, v in rep["provenance"].items()), ""]
    return "\n".join(L)
