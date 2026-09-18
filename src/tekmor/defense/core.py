"""The decision contract every defense implements, and the mediation entry point.

`docs/technical-doc.md` Part IV: every candidate action passes through
`Defense.decide(state, action, provenance, policy) -> Decision`. Routing all actions
through `mediate()` is what makes the defense a reference monitor with complete
mediation; failing closed there is what keeps an internal error from becoming an ALLOW.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from tekmor.policy.core import Policy
from tekmor.provenance.trust import Source, TrustLevel, least_trusted

logger = logging.getLogger(__name__)


class Verdict(Enum):
    """What the monitor does with a candidate action."""

    ALLOW = "allow"
    REWRITE = "rewrite"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Action:
    """A candidate tool call, before it reaches the world."""

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ActionProvenance:
    """The observations that influenced a candidate action.

    Field-level provenance and how this set is computed are Phase 2. What the decision
    core needs is the set and its meet.
    """

    sources: tuple[Source, ...] = ()

    @property
    def integrity(self) -> TrustLevel:
        """Biba integrity of the action: the minimum integrity of its influences."""
        return least_trusted(s.trust for s in self.sources)

    @classmethod
    def of(cls, sources: Iterable[Source]) -> ActionProvenance:
        return cls(tuple(sources))


@dataclass(frozen=True, slots=True)
class AgentState:
    """What the defense may see about the run besides the action itself.

    Deliberately thin. It must never carry scenario identifiers or expected outcomes —
    a defense that can recognise a test case is not evidence of security.
    """

    task: str = ""
    step: int = 0


@dataclass(frozen=True, slots=True)
class Decision:
    """The monitor's answer, with the reason codes the answer was computed from.

    `reason_codes` are coarse and public (the adaptive attacker sees them); fine-grained
    sub-scores belong in the private trace. They are faithful only as long as they name
    the predicates that actually fired, so never add one the decision did not use.
    """

    verdict: Verdict
    reason_codes: tuple[str, ...]
    rewritten: Action | None = None

    def __post_init__(self) -> None:
        if (self.verdict is Verdict.REWRITE) != (self.rewritten is not None):
            raise ValueError("a rewritten action is required by REWRITE and only by REWRITE")
        if not self.reason_codes:
            raise ValueError("a decision must name the reasons it was computed from")


@runtime_checkable
class Defense(Protocol):
    """Anything that can decide on a candidate action."""

    name: str

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision: ...


def mediate(
    defense: Defense,
    state: AgentState,
    action: Action,
    provenance: ActionProvenance,
    policy: Policy,
) -> Decision:
    """Call `defense`, failing closed.

    A monitor that crashes must not let the action through, and neither must one that
    returns something that is not a `Decision`. Every caller of a defense goes through
    here so that this property holds for all of them.
    """
    try:
        decision = defense.decide(state, action, provenance, policy)
    except Exception:
        logger.exception("defense %r raised; failing closed", getattr(defense, "name", defense))
        return Decision(Verdict.BLOCK, ("INTERNAL_ERROR",))
    if not isinstance(decision, Decision):
        logger.error(
            "defense %r returned %r; failing closed",
            getattr(defense, "name", defense),
            type(decision),
        )
        return Decision(Verdict.BLOCK, ("MALFORMED_DECISION",))
    return decision
