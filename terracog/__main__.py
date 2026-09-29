"""CLI: recommend REVERT / CODIFY / QUARANTINE / HUMAN_REVIEW for drift, render a benchmark case, run the benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import bench as bench_mod
from . import engine, scenarios


def _read(p) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _write(base: Path, report: dict, md: str) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8",
                                         newline="\n")
    base.with_suffix(".md").write_text(md, encoding="utf-8", newline="\n")
    print(f"wrote {base.with_suffix('.json')} and {base.with_suffix('.md')}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m terracog", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide", help="recommend an action for every drifted attribute in a plan")
    d.add_argument("--plan", required=True, help="terraform show -json output of a plan with resource_drift")
    d.add_argument("--events", required=True, help="CloudTrail log file ({\"Records\": [...]})")
    d.add_argument("--tickets", required=True, help="ITSM export ({\"tickets\": [...]})")
    d.add_argument("--world", default=str(scenarios.WORLD), help="services, SLO burn rates, policies, principals")
    d.add_argument("--report", help="write <report>.json and <report>.md (evidence)")
    r = sub.add_parser("render", help="write one benchmark case as plan/cloudtrail/tickets/world JSON")
    r.add_argument("case")
    r.add_argument("--out", default="build/case")
    b = sub.add_parser("bench", help="run the benchmark")
    b.add_argument("--seed", type=int, default=7, help="bootstrap seed (the decisions themselves are deterministic)")
    b.add_argument("--out", default="reports")
    a = ap.parse_args(argv)

    if a.cmd == "decide":
        inputs = [Path(a.plan), Path(a.events), Path(a.tickets), Path(a.world)]
        results = engine.decide(_read(a.plan), _read(a.events), _read(a.tickets), engine.load_world(Path(a.world)))
        for x in results:
            print(f"{x['action']:13s} {x['drift'].address}.{x['drift'].attr}  [{x['evidence']['intent']}] "
                  f"{x['evidence']['reason']}")
        if a.report:
            prov = engine.provenance(inputs)
            rep = {"decisions": [{"address": x["drift"].address, "attr": x["drift"].attr, "action": x["action"],
                                  "harm": x["harm"], "intent": x["evidence"]["intent"],
                                  "confidence": x["evidence"]["confidence"], "reason": x["evidence"]["reason"],
                                  "edges": x["evidence"]["edges"]} for x in results], "provenance": prov}
            _write(Path(a.report), rep, engine.evidence_markdown(results, prov))
        return 0
    world_raw = _read(scenarios.WORLD)
    cases = scenarios.load_cases()
    if a.cmd == "render":
        case = next((c for c in cases if c["id"] == a.case), None)
        if case is None:
            ap.error(f"unknown case {a.case!r}; one of: {', '.join(c['id'] for c in cases)}")
        scenarios.write(case, world_raw, Path(a.out))
        print(f"wrote {a.out}/plan.json cloudtrail.json tickets.json world.json  (SYNTHETIC; label: {case['label']})")
        return 0
    rep = bench_mod.bench(cases, world_raw, a.seed)
    rep["provenance"] = engine.provenance([scenarios.WORLD, scenarios.CASES], seed=a.seed,
                                          fixtures="fixtures/world.json + fixtures/cases.json")
    for m, x in rep["summary"].items():
        print(f"{m:32s} correct {x['correct']:2d}/{x['n']}  mean CDR {x['mean_cdr']}")
    _write(Path(a.out) / "benchmark", rep, bench_mod.markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
