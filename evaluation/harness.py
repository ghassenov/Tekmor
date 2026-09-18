"""The evaluation harness: every scenario against every defense, scored and recorded.

    uv run python -m evaluation.harness

`docs/technical-doc.md` Part VI. This is the first thing in the repository that produces
a *number*; everything before it produced behaviour. What it does is small on purpose —
load the scenario matrix, run each scenario under each defense through the ordinary
`tekmor.runtime.run`, score the finished worlds with `evaluation.metrics`, and write the
run down well enough that someone else can reproduce it.

**Raw is write-once.** Each invocation gets its own directory under `results/raw/`
(decision events, per-run records, and the manifest that says how they were produced),
and the aggregate lands under `results/processed/`. Analysis never edits raw output; it
reads it and writes somewhere else (`evaluation/CLAUDE.md`).

**Nothing the scorer knows reaches a defense.** The defenses are constructed here from
the scenario files' *canary values* and nothing else — that registry is the organization's
own list of secrets, the DLP analogue, and is a deployment input rather than scenario
metadata (`src/defense/canary.py`). Scenario ids, `benign`, and the outcome conditions
stay on this side of the boundary; `run()` hands a defense only state, action, provenance
and policy.

**The runs are deterministic**, so the numbers are reproducible without a seed: the
scripted adapter replays the scenario's steps, the worlds are rebuilt per run, and the
simulated human denies every escalation. A model-driven run is not deterministic and will
need its seed and decoding parameters recorded in the manifest; the field is there and
says `scripted` today.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from evaluation.metrics import RunRecord, by_defense, record, table
from tekmor import __version__
from tekmor.defense import CanaryScanner, Defense, ReferenceMonitor
from tekmor.defense.baselines import AllowAll, DenySensitive, KeywordFilter
from tekmor.observability import EventLog
from tekmor.runtime import run
from tekmor.simulator import load_scenario
from tekmor.simulator.scenario import Scenario

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = REPO / "evaluation" / "scenarios"
RESULTS = REPO / "evaluation" / "results"


def defenses(secrets: frozenset[str]) -> tuple[Defense, ...]:
    """The defenses under test, baselines first.

    The three baselines bracket the space (`src/defense/baselines.py`), `tekmor` is the
    deterministic core, and `tekmor+canary` adds the argument scan. The last two are one
    ablation pair already: the difference between their rows is exactly what CANARY-FLOW
    contributes, which is the only honest way to claim it contributes anything.
    """
    monitor = ReferenceMonitor()
    return (
        AllowAll(),
        DenySensitive(),
        KeywordFilter(),
        monitor,
        CanaryScanner(monitor, secrets),
    )


def load_matrix(directory: Path) -> tuple[Scenario, ...]:
    """Load every scenario in `directory`, in a stable order so runs are comparable."""
    paths = sorted(
        path for path in directory.iterdir() if path.suffix in {".json", ".yaml", ".yml"}
    )
    if not paths:
        raise SystemExit(f"no scenarios in {directory}")
    return tuple(load_scenario(path) for path in paths)


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):  # a tarball checkout has no git
        return ""


def manifest(scenarios: Iterable[Scenario], names: Sequence[str], directory: Path) -> dict:
    """Everything needed to say how a result was produced (`evaluation/CLAUDE.md`).

    The commit *and* whether the tree was dirty, because a result produced from
    uncommitted edits is not reproducible from the commit alone and should say so
    rather than look clean.
    """
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "tekmor_version": __version__,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "adapter": "scripted",
        "seed": None,
        "approver": "deny",
        "scenario_dir": str(directory),
        "defenses": list(names),
        "scenarios": [
            {
                "id": scenario.id,
                "version": scenario.version,
                "domain": scenario.domain,
                "benign": scenario.benign,
            }
            for scenario in scenarios
        ],
    }


def digest(directory: Path) -> dict[str, str]:
    """SHA-256 per scenario file: the run's inputs, pinned by content rather than name."""
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.suffix in {".json", ".yaml", ".yml"}
    }


def evaluate(scenarios: Sequence[Scenario], log: EventLog | None = None) -> list[RunRecord]:
    """Run the full matrix and score it. Each run gets a fresh world and a fresh taint."""
    secrets = frozenset(value for scenario in scenarios for value in scenario.canaries.values())
    return [
        record(scenario, run(scenario, defense, log=log))
        for defense in defenses(secrets)
        for scenario in scenarios
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=Path, default=SCENARIOS)
    parser.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args(argv)

    scenarios = load_matrix(args.scenarios)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    raw = args.results / "raw" / stamp
    processed = args.results / "processed" / stamp
    raw.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)

    log = EventLog(raw / "decisions.jsonl")
    records = evaluate(scenarios, log)
    metrics = by_defense(records)

    (raw / "runs.jsonl").write_text(
        "".join(json.dumps(item.as_dict(), sort_keys=True) + "\n" for item in records),
        encoding="utf-8",
    )
    (raw / "manifest.json").write_text(
        json.dumps(
            {
                **manifest(scenarios, list(metrics), args.scenarios),
                "inputs": digest(args.scenarios),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (processed / "metrics.json").write_text(
        json.dumps({name: m.as_dict() for name, m in metrics.items()}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    print(table(metrics))
    print(f"\n{len(records)} runs -> {raw}\n            -> {processed / 'metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
