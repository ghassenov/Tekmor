"""Append-only JSONL event log.

One line per mediated action. `docs/technical-doc.md` Part V lists the full event
schema; this carries the fields that exist in the current implementation. Fields are
added as the components that produce them land — an event never claims a signal the
decision did not use.

Argument *values* are never written. Until the simulator's canary registry exists there
is nothing to redact them against, and the rule is that secrets and canary values never
reach the log. Argument names are enough to reconstruct which call was decided on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tekmor.defense.core import Action, ActionProvenance, Decision
from tekmor.provenance.trust import TrustLevel


@dataclass(frozen=True, slots=True)
class DecisionEvent:
    """What one `Defense.decide` call saw and answered."""

    run_id: str
    step: int
    defense: str
    tool: str
    arg_names: tuple[str, ...]
    source_ids: tuple[str, ...]
    integrity: TrustLevel
    verdict: str
    reason_codes: tuple[str, ...]
    rewritten_tool: str | None
    timestamp: str

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "step": self.step,
            "defense": self.defense,
            "tool": self.tool,
            "arg_names": list(self.arg_names),
            "source_ids": list(self.source_ids),
            "integrity": self.integrity.name,
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "rewritten_tool": self.rewritten_tool,
            "timestamp": self.timestamp,
        }


def decision_event(
    run_id: str,
    step: int,
    defense: str,
    action: Action,
    provenance: ActionProvenance,
    decision: Decision,
) -> DecisionEvent:
    """Build the event for one decision from the objects the monitor already has."""
    return DecisionEvent(
        run_id=run_id,
        step=step,
        defense=defense,
        tool=action.tool,
        arg_names=tuple(action.args),
        source_ids=tuple(s.id for s in provenance.sources),
        integrity=provenance.integrity,
        verdict=decision.verdict.value,
        reason_codes=decision.reason_codes,
        rewritten_tool=decision.rewritten.tool if decision.rewritten else None,
        timestamp=datetime.now(UTC).isoformat(),
    )


class EventLog:
    """Append-only JSONL file. Opened per write, so a crash keeps what was already logged."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: DecisionEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
