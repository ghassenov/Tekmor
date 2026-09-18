"""Append-only JSONL event log.

One line per mediated action. `docs/technical-doc.md` Part V lists the full event
schema; this carries the fields that exist in the current implementation. Fields are
added as the components that produce them land — an event never claims a signal the
decision did not use.

The *aggregate* risk score is logged and the per-signal contributions are not. The
schema asks for both, and the breakdown is the half that is a hill-climbing channel
(`defense/CLAUDE.md`), so it stays derivable from the signals rather than written next
to a verdict an attacker may get to see. `defense.risk.contributions` computes it.

Argument *values* are never written, and the rule holds whether or not a value is a
known secret: redacting against the canary registry would protect the values someone
remembered to register and no others, and a trace is not the place to find out which
those were. Argument names are enough to reconstruct which call was decided on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tekmor.defense.core import Action, ActionProvenance, Decision
from tekmor.policy.core import Policy
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
    confidential: bool
    policy: str
    policy_version: int
    verdict: str
    reason_codes: tuple[str, ...]
    #: The aggregate risk score, or None for a defense that emits no score. Null and
    #: 0.0 are different claims and the log keeps them apart.
    risk: float | None
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
            "confidential": self.confidential,
            "policy": self.policy,
            "policy_version": self.policy_version,
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "risk": self.risk,
            "rewritten_tool": self.rewritten_tool,
            "timestamp": self.timestamp,
        }


def decision_event(
    run_id: str,
    step: int,
    defense: str,
    action: Action,
    provenance: ActionProvenance,
    policy: Policy,
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
        confidential=provenance.confidential,
        # The policy a decision was computed under is part of the decision: a trace
        # without it cannot be replayed, because the rules may have moved since.
        policy=policy.name,
        policy_version=policy.version,
        verdict=decision.verdict.value,
        reason_codes=decision.reason_codes,
        risk=decision.risk,
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
