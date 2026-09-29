"""Scenario renderer: expands one compact, labelled case into the files the engine reads.

Output formats follow the real tools: `terraform show -json` (format_version 1.2, as emitted by
Terraform 1.16), CloudTrail log records and a minimal ITSM export. The engine never sees the labels.
"""
from __future__ import annotations

import copy
import datetime
import json
import uuid
from pathlib import Path

from .engine import ACTIONS, ROOT, World

WORLD = ROOT / "fixtures" / "world.json"
CASES = ROOT / "fixtures" / "cases.json"
PLAN_TIME = datetime.datetime(2026, 9, 1, 12, 0, tzinfo=datetime.timezone.utc)
SOURCES = {"aws_security_group": "ec2", "aws_ebs_encryption_by_default": "ec2", "aws_autoscaling_group": "autoscaling",
           "aws_ecs_service": "ecs", "aws_db_instance": "rds", "aws_elasticache_replication_group": "elasticache",
           "aws_s3_bucket_public_access_block": "s3", "aws_route53_record": "route53", "aws_iam_role_policy": "iam",
           "aws_lb_listener": "elasticloadbalancing", "aws_lambda_function": "lambda"}
SERVICE_ROLES = {"AWSServiceRoleForAutoScaling": "autoscaling.amazonaws.com",
                 "AWSServiceRoleForApplicationAutoScaling_ECSService": "ecs.application-autoscaling.amazonaws.com",
                 "AWSServiceRoleForRDS": "rds.amazonaws.com"}


def load_cases(path: Path = CASES) -> list[dict]:
    cases = json.loads(Path(path).read_text(encoding="utf-8"))["cases"]
    for c in cases:
        if set(c["harm"]) != set(ACTIONS):
            raise ValueError(f"{c['id']}: harm must define every action")
        best = min(c["harm"].values())
        if [a for a in ACTIONS if c["harm"][a] == best] != [c["label"]]:
            raise ValueError(f"{c['id']}: label must be the unique lowest-harm action")
    return cases


def _plan(c: dict, world: dict) -> dict:
    rtype, name = c["resource"].split(".", 1)
    rid = world["resources"][c["resource"]]["id"]
    base = {"address": c["resource"], "mode": "managed", "type": rtype, "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws"}
    state, live = {"id": rid, c["attr"]: c["iac"]}, {"id": rid, c["attr"]: c["live"]}
    change = lambda before, after: {"actions": ["update"], "before": before, "after": after, "after_unknown": {},
                                    "before_sensitive": {}, "after_sensitive": {}}
    return {"format_version": "1.2", "terraform_version": "1.16.2",
            "resource_drift": [{**base, "change": change(state, live)}],
            "resource_changes": [{**base, "change": change(live, state)}],  # what an apply would do: revert
            "timestamp": PLAN_TIME.isoformat().replace("+00:00", "Z"), "applyable": True, "complete": True,
            "errored": False}


def _record(c: dict, e: dict, world: dict, n: int) -> dict:
    rtype = c["resource"].split(".", 1)[0]
    acct = world["account"]
    head, _, session = e["who"].partition("/")
    t = PLAN_TIME - datetime.timedelta(minutes=e["ago_min"])
    if head == "user":
        uid = {"type": "IAMUser", "arn": f"arn:aws:iam::{acct}:user/{session}", "accountId": acct, "userName": session}
    else:
        uid = {"type": "AssumedRole", "arn": f"arn:aws:sts::{acct}:assumed-role/{head}/{session}", "accountId": acct,
               "sessionContext": {"sessionIssuer": {"type": "Role", "userName": head,
                                                    "arn": f"arn:aws:iam::{acct}:role/{head}"}}}
        if head in SERVICE_ROLES:
            uid["invokedBy"] = SERVICE_ROLES[head]
    return {"eventVersion": "1.10", "eventTime": t.isoformat().replace("+00:00", "Z"),
            "eventSource": f"{SOURCES[rtype]}.amazonaws.com", "eventName": e["api"], "awsRegion": "eu-west-1",
            "sourceIPAddress": SERVICE_ROLES.get(head, "198.51.100.7"), "userAgent": "console.amazonaws.com",
            "userIdentity": uid, "requestParameters": {c["attr"]: c["live"]},
            "resources": [{"ARN": world["resources"][c["resource"]]["id"], "accountId": acct, "type": rtype}],
            "eventID": str(uuid.uuid5(uuid.NAMESPACE_URL, f"terracog/{c['id']}/{n}")), "readOnly": False}


def render(c: dict, world_raw: dict) -> tuple[dict, dict, dict, World]:
    """(plan, cloudtrail, tickets, world) for one case. SYNTHETIC."""
    w = copy.deepcopy(world_raw)
    w["burn_rates"] = dict(c.get("burn", {}))
    trail = {"Records": [_record(c, e, world_raw, n) for n, e in enumerate(c["events"])]}
    tickets = {"tickets": [{"id": k, **v} for k, v in sorted(c["tickets"].items())]}
    return _plan(c, world_raw), trail, tickets, World(w, w["burn_rates"])


def write(c: dict, world_raw: dict, out: Path) -> None:
    plan, trail, tickets, world = render(c, world_raw)
    out.mkdir(parents=True, exist_ok=True)
    for name, doc in (("plan", plan), ("cloudtrail", trail), ("tickets", tickets), ("world", world.raw)):
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
