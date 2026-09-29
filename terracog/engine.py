"""Intent Delta Graph and the counterfactual decision: for each drifted attribute, which source of truth wins?

Inputs are the formats operators already have: a Terraform plan (`terraform show -json`), CloudTrail
records, an ITSM ticket export and a small world file (service graph, SLO burn rates, policies,
principal directory). Nothing here calls a cloud API or an LLM; the output is a recommendation.
"""
from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ACTIONS = ("REVERT", "CODIFY", "QUARANTINE", "HUMAN_REVIEW")
TIE_ORDER = ("HUMAN_REVIEW", "QUARANTINE", "REVERT", "CODIFY")  # on equal harm, prefer the more reversible action
TIER_WEIGHT = {1: 4.0, 2: 2.0, 3: 1.0}
TICKET_RE = re.compile(r"\b(?:INC|CHG)-\d+\b")

# What each inferred intent costs on top of the security and availability deltas.
# L: extra harm if we REVERT (the intent is lost), K: extra harm if we CODIFY (the change is legitimised),
# Q: harm of holding live state (0 where a hold is the designed response). "stake" = SLO stake of the service.
INTENTS = {
    "emergency_active":   {"L": lambda stake, p: stake, "K": 2, "Q": 0},
    "emergency_resolved": {"L": lambda stake, p: 2, "K": 0, "Q": 2},
    "approved_change":    {"L": lambda stake, p: 2, "K": 0, "Q": 2},
    "controller":         {"L": lambda stake, p: 3, "K": 3, "Q": 0},
    "ad_hoc":             {"L": lambda stake, p: 0, "K": 1, "Q": 2},
    "unverified":         {"L": lambda stake, p: 0, "K": 3, "Q": 2},
    "suspicious":         {"L": lambda stake, p: 0, "K": 6, "Q": 3},
    "unknown":            {"L": lambda stake, p: 0.5 * stake * p, "K": 2, "Q": 2},  # it may have been a fix
}


@dataclass(frozen=True)
class Drift:
    address: str
    type: str
    attr: str
    iac: object
    live: object
    resource_id: str


@dataclass(frozen=True)
class Event:
    time: str
    api: str
    role: str          # IAM role name, or "user/<name>" for an IAM user
    session: str
    resource_ids: tuple
    ticket: str | None


@dataclass
class World:
    raw: dict
    burn: dict = field(default_factory=dict)

    def __getitem__(self, k):
        return self.raw[k]

    def service(self, address: str) -> str:
        return self.raw["resources"][address]["service"]

    def dependents(self, svc: str) -> set:
        """Services that transitively depend on svc: who breaks if svc breaks."""
        rev: dict = {}
        for s, v in self.raw["services"].items():
            for d in v["depends_on"]:
                rev.setdefault(d, set()).add(s)
        out, todo = set(), [svc]
        while todo:
            for s in rev.get(todo.pop(), ()):
                if s not in out:
                    out.add(s)
                    todo.append(s)
        return out

    def burn_rate(self, svc: str) -> float:
        return self.burn.get(svc, self.raw["default_burn_rate"])

    def kind(self, rtype: str, attr: str) -> str:
        k = self.raw["attr_kinds"]
        return k.get(f"{rtype}.{attr}") or k.get(f"*.{attr}") or "config"


def load_world(path: Path) -> World:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return World(raw, raw.get("burn_rates", {}))


# ---------------------------------------------------------------- input parsers (real formats)

def parse_plan(plan: dict) -> list[Drift]:
    """One Drift per attribute that differs in `resource_drift` (prior state vs refreshed live object).

    The IaC value is the configured value from `resource_changes[].change.after` when present (what an apply
    would write back), else the prior state. Only in-place updates are handled; deletes are out of scope.
    """
    config = {rc["address"]: rc["change"].get("after") or {} for rc in plan.get("resource_changes", [])}
    out = []
    for rd in plan.get("resource_drift", []):
        ch = rd["change"]
        if ch["actions"] != ["update"]:
            raise ValueError(f"{rd['address']}: only in-place drift is supported, got {ch['actions']}")
        before, after = ch["before"], ch["after"]
        for attr in sorted(set(before) | set(after)):
            if attr != "id" and before.get(attr) != after.get(attr):
                iac = config.get(rd["address"], {}).get(attr, before.get(attr))
                out.append(Drift(rd["address"], rd["type"], attr, iac, after.get(attr), after.get("id") or before["id"]))
    return out


def parse_cloudtrail(doc: dict) -> list[Event]:
    out = []
    for r in doc.get("Records", []):
        uid = r["userIdentity"]
        if uid["type"] == "AssumedRole":  # arn:aws:sts::<acct>:assumed-role/<role>/<session>
            _, role, session = uid["arn"].split(":", 5)[5].split("/", 2)
        else:  # IAMUser and anything else: identified by the ARN tail, never trusted by name alone
            role, session = uid["arn"].split(":", 5)[5], ""
        m = TICKET_RE.search(session)
        out.append(Event(r["eventTime"], r["eventName"], role, session,
                         tuple(x["ARN"] for x in r.get("resources", [])), m.group(0) if m else None))
    return out


def parse_tickets(doc: dict) -> dict:
    return {t["id"]: t for t in doc.get("tickets", [])}


# ---------------------------------------------------------------- Intent Delta Graph

def link(d: Drift, events: list[Event], tickets: dict, world: World) -> dict:
    """The drift's neighbourhood in the IDG: resource -> service -> dependents, events -> principal -> ticket,
    attribute -> policies. Returned as evidence so every decision can be audited."""
    svc = world.service(d.address)
    attrs = world["event_attrs"]
    touching = [e for e in events if d.resource_id in e.resource_ids and d.attr in attrs.get(e.api, [d.attr])]
    ev = max(touching, key=lambda e: e.time) if touching else None
    ticket = tickets.get(ev.ticket) if ev and ev.ticket else None
    edges = [(d.address, "part_of", svc), *((svc, "depended_on_by", s) for s in sorted(world.dependents(svc)))]
    if ev:
        edges += [(d.address, "changed_by", f"{ev.api}@{ev.time}"), (f"{ev.api}@{ev.time}", "principal", ev.role)]
        if ev.ticket:
            edges.append((ev.role, "cites", ev.ticket + ("" if ticket else " (not found)")))
    return {"service": svc, "tier": world["services"][svc]["tier"], "dependents": sorted(world.dependents(svc)),
            "burn_rate": world.burn_rate(svc), "event": ev, "ticket_id": ev.ticket if ev else None,
            "ticket": ticket, "policies_live": violations(d.type, d.attr, d.live, world),
            "policies_iac": violations(d.type, d.attr, d.iac, world), "kind": world.kind(d.type, d.attr),
            "edges": edges}


def violations(rtype: str, attr: str, value, world: World) -> list[dict]:
    out = []
    for p in world["policies"]:
        if p["attr"] != attr or p["type"] not in ("*", rtype) or value is None:
            continue
        vals = value if isinstance(value, list) else [value]
        if p["op"] == "eq":
            hit = value == p["value"]
        elif p["op"] == "lt":
            hit = value < p["value"]
        elif p["op"] == "lacks_key":
            hit = p["value"] not in value
        else:  # match: any element matches any pattern and no exception
            hit = any(isinstance(v, str) and any(fnmatch.fnmatchcase(v, g) for g in p["value"])
                      and v not in p.get("except", []) for v in vals)
        if hit:
            out.append({"id": p["id"], "severity": p["severity"]})
    return out


def infer_intent(ev: Event | None, ticket: dict | None, d: Drift, svc: str, world: World) -> tuple[str, float, str]:
    """(intent, confidence, reason). Confidence is how much the provenance is trusted, not a probability model."""
    if ev is None:
        return "unknown", 0.0, "no audit event touches this attribute"
    cls = world["principals"].get(ev.role)
    if cls is None:
        return "suspicious", 0.8, f"principal {ev.role} is not in the directory"
    if cls == "controller":
        owned = world["controller_fields"].get(ev.role, {}).get(d.type, [])
        return ("controller", 0.95, f"{ev.role} owns {d.type}.{d.attr}") if d.attr in owned else \
            ("unverified", 0.5, f"controller {ev.role} changed a field it does not own")
    if cls == "iac":
        return "approved_change", 0.6, "applied by the IaC pipeline from outside this workspace"
    if ev.ticket is None:
        return ("unverified", 0.7, "break-glass session without a ticket") if cls == "breakglass" else \
            ("ad_hoc", 0.7, f"{ev.role} changed it without citing a ticket")
    if ticket is None:
        return "unverified", 0.8, f"cited {ev.ticket} does not exist"
    if ticket["service"] != svc:
        return "unverified", 0.8, f"{ev.ticket} is for {ticket['service']}, not {svc}"
    if ticket["kind"] == "incident":
        if ticket["status"] == "open":
            return "emergency_active", 0.9 if cls == "breakglass" else 0.75, f"{ev.ticket} is an open incident on {svc}"
        return "emergency_resolved", 0.8, f"{ev.ticket} is a resolved incident on {svc}"
    if ticket["status"] == "approved":
        return "approved_change", 0.85, f"{ev.ticket} is an approved change for {svc}"
    return "unverified", 0.8, f"{ev.ticket} has status {ticket['status']}"


def _level(v, attr: str, world: World) -> float:
    ranks = world["ranks"].get(attr)
    return float(ranks.index(v) + 1) if ranks else float(v)


def counterfactuals(d: Drift, ev: dict, world: World, *, use_intent: bool = True, use_blast: bool = True) -> dict:
    """Estimated harm (0-10ish) of each action. REVERT and CODIFY are the two counterfactual end states;
    QUARANTINE and HUMAN_REVIEW keep live state for days or hours respectively."""
    stake = TIER_WEIGHT[ev["tier"]] * ((1 + 0.5 * len(ev["dependents"])) if use_blast else 1)
    stake = min(stake, 10.0)
    pressure = 1.0 if ev["burn_rate"] >= 1 else 0.25  # is the service burning error budget right now?
    sec_live = max((p["severity"] for p in ev["policies_live"]), default=0)
    sec_iac = max((p["severity"] for p in ev["policies_iac"]), default=0)
    avail_live = avail_iac = 0.0
    if ev["kind"] == "capacity":
        a, b = _level(d.iac, d.attr, world), _level(d.live, d.attr, world)
        delta = (b - a) / max(a, b, 1.0)          # > 0: live has more capacity than code
        avail_live = stake * max(0.0, -delta)      # keeping a capacity cut
        avail_iac = stake * max(0.0, delta) * pressure  # removing capacity the service may be using
    elif ev["kind"] == "routing":
        avail_iac = stake * pressure               # moving traffic back while the service is degraded
    impact = 0.0 if ev["kind"] == "cosmetic" else stake

    def harms(intent: str) -> dict:
        p = INTENTS[intent]
        exposure = sec_live + avail_live
        return {"REVERT": sec_iac + avail_iac + p["L"](impact, pressure),
                "CODIFY": sec_live + avail_live + p["K"],
                "QUARANTINE": p["Q"] + 0.6 * exposure,
                "HUMAN_REVIEW": 1 + 0.3 * exposure}

    intent, conf = (ev["intent"], ev["confidence"]) if use_intent else ("unknown", 0.0)
    hi, hu = harms(intent), harms("unknown")
    return {a: round(conf * hi[a] + (1 - conf) * hu[a], 3) for a in ACTIONS}


def choose(harm: dict) -> str:
    return min(TIE_ORDER, key=lambda a: (harm[a], TIE_ORDER.index(a)))


def analyse(d: Drift, events: list[Event], tickets: dict, world: World, **ablate) -> dict:
    ev = link(d, events, tickets, world)
    ev["intent"], ev["confidence"], ev["reason"] = infer_intent(ev["event"], ev["ticket"], d, ev["service"], world)
    harm = counterfactuals(d, ev, world, **ablate)
    return {"drift": d, "evidence": ev, "harm": harm, "action": choose(harm)}


def decide(plan: dict, trail: dict, tickets: dict, world: World, **ablate) -> list[dict]:
    events, tix = parse_cloudtrail(trail), parse_tickets(tickets)
    return [analyse(d, events, tix, world, **ablate) for d in parse_plan(plan)]


# ---------------------------------------------------------------- reports

def _fmt(v) -> str:
    s = json.dumps(v)
    return s if len(s) <= 60 else s[:57] + "..."


def evidence_markdown(results: list[dict], prov: dict) -> str:
    L = ["# TERRACOG drift decisions", "",
         "_Recommendations only. Nothing was applied. Harm is the model's estimate (see README)._", "",
         "| Resource | Attribute | IaC | Live | Intent | Action |", "|---|---|---|---|---|---|"]
    for r in results:
        d, e = r["drift"], r["evidence"]
        L.append(f"| `{d.address}` | `{d.attr}` | `{_fmt(d.iac)}` | `{_fmt(d.live)}` | {e['intent']} | **{r['action']}** |")
    for r in results:
        d, e = r["drift"], r["evidence"]
        ev = e["event"]
        L += ["", f"## `{d.address}.{d.attr}` -> {r['action']}", "",
              f"- Intent: **{e['intent']}** (confidence {e['confidence']}): {e['reason']}",
              f"- Last change: " + (f"`{ev.api}` by `{ev.role}/{ev.session}` at {ev.time}" if ev else "none found"),
              f"- Ticket: {e['ticket_id'] or 'none'}" + (f" ({e['ticket']['kind']}, {e['ticket']['status']}, "
                                                         f"{e['ticket']['service']})" if e["ticket"] else ""),
              f"- Service: {e['service']} (tier {e['tier']}, burn rate {e['burn_rate']}), "
              f"dependents: {', '.join(e['dependents']) or 'none'}",
              f"- Policies violated by live: {', '.join(p['id'] for p in e['policies_live']) or 'none'}; "
              f"by IaC: {', '.join(p['id'] for p in e['policies_iac']) or 'none'}", "",
              "| Action | Estimated harm |", "|---|---|",
              *(f"| {a} | {r['harm'][a]} |" for a in ACTIONS), "",
              "Graph edges: " + "; ".join(f"{a} -{rel}-> {b}" for a, rel, b in e["edges"])]
    L += ["", "## Provenance", "", *(f"- {k}: `{v}`" for k, v in prov.items()), ""]
    return "\n".join(L)


def provenance(inputs: list[Path], **extra) -> dict:
    def git(*args):
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    sha = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", "terracog", "fixtures"))
    h = hashlib.sha256()
    for p in inputs:
        h.update(Path(p).read_bytes())
    return {"commit": (sha or "unknown") + ("-dirty" if dirty else ""),
            "command": "python -m terracog " + " ".join(sys.argv[1:]),
            "python": platform.python_version(), "platform": platform.platform(),
            "inputs_sha256": h.hexdigest()[:16],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            **extra}
