"""Signal extraction: the named predicates a decision is computed from.

`docs/technical-doc.md` Part IV stage 2. The monitor used to call the policy predicates
inline, which was correct but left the signals implicit: there was nothing a risk score,
a trace line or a viewer could read without re-deriving them, and a second reader of the
same facts is a second chance to disagree with the decision.

So the predicates are evaluated **once**, here, into a value the decision and the risk
score both read. That is what makes the reason codes and the score faithful in the sense
`defense/CLAUDE.md` means: not "consistent with" the decision but computed from the same
object it was.

Nothing here decides. Nothing here reads a clock, a model or the world — the signals are
a pure function of the four inputs the monitor is handed, which is what keeps a replayed
trace comparable to the run that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass

from tekmor.defense.core import Action, ActionProvenance, AgentState
from tekmor.policy.core import (
    Policy,
    downgrade_for,
    permitted_flow,
    permitted_tool,
    recipients_of,
    trusted_action,
)
from tekmor.provenance.trust import TrustLevel


@dataclass(frozen=True, slots=True)
class Signals:
    """The facts about one candidate action, as the policy sees them.

    Deliberately small: every field is used by `monitor.ReferenceMonitor` or by
    `risk.score`, and a field neither uses would be a signal nothing was computed from.

    The recipients themselves are *not* here. They are checked (`flow_permitted`) and
    then dropped, because a destination is part of what a run is trying to keep in and
    this object is what the risk contributions and the trace are rendered from.
    """

    tool: str
    tool_permitted: bool
    tool_sensitive: bool
    tool_outbound: bool
    integrity: TrustLevel
    #: Trusted-Action: may inputs of this integrity drive this tool?
    integrity_sufficient: bool
    confidential_influence: bool
    #: Permitted-Flow: may what influenced this action leave through this call?
    flow_permitted: bool
    #: The lower-capability variant the policy declares, if it vetted one
    #: (`policy.downgrade_for`), else None.
    downgrade: str | None
    #: The Trusted-Action threshold this was judged against, kept so a contribution and
    #: a trace line can be read without the policy that produced them.
    min_integrity: TrustLevel

    @property
    def untrusted_influence(self) -> bool:
        """Whether anything below the policy's integrity threshold influenced the action.

        True on a *non*-sensitive tool as well, where it is not a violation: the agent
        is allowed to read hostile content, and this is the signal saying it did. It is
        the gray-zone input a secondary sensor would arbitrate on (Proposal B), and it
        carries a small risk contribution rather than a verdict.
        """
        return self.integrity < self.min_integrity


def extract(
    state: AgentState,
    action: Action,
    provenance: ActionProvenance,
    policy: Policy,
) -> Signals:
    """Evaluate every policy predicate for one candidate action.

    `state` is accepted and unused. It is part of the decision contract and of this
    stage's signature so that a signal computed from the run's history (step index, task)
    lands here rather than in a second extractor; nothing needs it yet.
    """
    confidential = provenance.confidential
    integrity = provenance.integrity
    return Signals(
        tool=action.tool,
        tool_permitted=permitted_tool(action.tool, policy),
        tool_sensitive=action.tool in policy.sensitive_tools,
        tool_outbound=action.tool in policy.outbound_tools,
        integrity=integrity,
        integrity_sufficient=trusted_action(action.tool, integrity, policy),
        confidential_influence=confidential,
        flow_permitted=permitted_flow(
            action.tool, confidential, recipients_of(action.args, policy), policy
        ),
        downgrade=downgrade_for(action.tool, policy),
        min_integrity=policy.min_integrity,
    )
