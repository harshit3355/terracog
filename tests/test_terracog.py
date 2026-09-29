import json

import pytest

from terracog import bench, engine, scenarios

WORLD = json.loads(scenarios.WORLD.read_text(encoding="utf-8"))
CASES = scenarios.load_cases()
BY_ID = {c["id"]: c for c in CASES}


def _decide(case):
    plan, trail, tickets, world = scenarios.render(case, WORLD)
    (r,) = engine.decide(plan, trail, tickets, world)
    return r


def test_benchmark_is_large_enough_and_labels_are_the_unique_argmin():
    assert 40 <= len(CASES) <= 60 and len({c["id"] for c in CASES}) == len(CASES)
    assert sum(bool(c.get("negative")) for c in CASES) >= 1
    assert {c["label"] for c in CASES} == set(engine.ACTIONS)  # load_cases already checked argmin


def test_rendered_plan_round_trips_through_the_real_format_parser():
    c = BY_ID["iam-wildcard-adhoc"]
    plan, trail, _, _ = scenarios.render(c, WORLD)
    assert plan["format_version"] == "1.2" and plan["resource_changes"][0]["change"]["after"]["policy"] == c["iac"]
    (d,) = engine.parse_plan(plan)
    assert (d.address, d.attr, d.iac, d.live) == (c["resource"], c["attr"], c["iac"], c["live"])
    (e,) = engine.parse_cloudtrail(trail)
    assert (e.role, e.ticket) == ("developer", None)


def test_cloudtrail_identity_and_ticket_extraction():
    trail = {"Records": [
        {"eventTime": "t1", "eventName": "X", "resources": [{"ARN": "r"}],
         "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/breakglass-oncall/alice@INC-7"}},
        {"eventTime": "t2", "eventName": "X", "resources": [{"ARN": "r"}],
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/breakglass-oncall"}}]}
    a, b = engine.parse_cloudtrail(trail)
    assert (a.role, a.session, a.ticket) == ("breakglass-oncall", "alice@INC-7", "INC-7")
    assert b.role == "user/breakglass-oncall"  # an IAM user named like a trusted role is not that role


def test_same_drift_flips_with_provenance():
    """The mechanism: an identical capacity change is held during an open incident, never held for a stranger."""
    c = BY_ID["hotfix-checkout-min-size"]
    assert _decide(c)["action"] == "QUARANTINE"
    stranger = {**c, "events": [{**c["events"][0], "who": "user/svc-legacy"}]}
    assert _decide(stranger)["action"] not in ("QUARANTINE", "CODIFY")


def test_never_codifies_a_high_severity_policy_violation():
    for c in CASES:
        r = _decide(c)
        if max((p["severity"] for p in r["evidence"]["policies_live"]), default=0) >= 7:
            assert r["action"] != "CODIFY", c["id"]


def test_mechanism_beats_every_baseline_and_the_provenance_ablations():
    s = bench.bench(CASES, WORLD, seed=7)["summary"]
    tc = s["terracog"]["mean_cdr"]
    for m in ("always_revert", "always_codify", "always_human_review", "severity_only",
              "intent_rules_no_counterfactual", "counterfactual_no_intent"):
        assert tc < s[m]["mean_cdr"], m


@pytest.mark.parametrize("case_id", ["NEG-spoofed-breakglass", "NEG-audit-log-gap", "NEG-stale-incident",
                                     "NEG-cost-not-modelled"])
def test_known_blind_spots_stay_documented(case_id):
    """Negative cases: if one starts passing, the README's failure analysis is out of date."""
    assert _decide(BY_ID[case_id])["action"] != BY_ID[case_id]["label"]
