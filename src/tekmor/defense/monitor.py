"""The reference monitor: the policy rules turned into a verdict.

`docs/technical-doc.md` Part VII, Proposal A. The policy engine
(`tekmor.policy.core`) answers two yes/no questions about a candidate action; this
module decides what to *do* about a no, which is where ALLOW / REWRITE / ESCALATE /
BLOCK are chosen.

The ordering of the checks is the design, and it is fixed:

1. **Least privilege.** A tool the policy does not permit is blocked before anything
   else is considered.
2. **Permitted-Flow.** A confidential value heading out to an unauthorized recipient is
   blocked. There is no safe downgrade of an exfiltration: a lower-capability variant
   that still carries the value has only moved it, and escalating hands a human a
   decision they cannot check, because the value is not in the argument in a form they
   would recognise.
3. **Trusted-Action.** A sensitive tool driven by inputs below the integrity threshold
   is downgraded to its lower-capability variant when the policy declares one, and
   escalated to a human when it does not. This is the branch that exists so the answer
   to an injection is not always "stop working": the SOC analyst still gets a ticket,
   and the drafted mail is still there for a human to send.

Everything this decides is computed from the four inputs it is handed. It never sees the
scenario, the world, the file it came from, or whether the run is supposed to be an
attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Verdict,
)
from tekmor.policy.core import (
    Policy,
    downgrade_for,
    permitted_flow,
    permitted_tool,
    recipients_of,
    trusted_action,
)


@dataclass(frozen=True, slots=True)
class ReferenceMonitor:
    """Tekmor's deterministic core: provenance and policy, no text matching, no model.

    It reads the *provenance* of the action rather than its arguments, so the encodings
    and paraphrases that defeat `baselines.KeywordFilter` change nothing here: a base64
    copy of a secret was still influenced by the read that produced it.

    The reverse is the honest limitation, and it is the one to measure: the monitor sees
    only the sources it is handed, and taint propagation hands it call-level influence.
    A value that reached an argument without passing through a labelled observation is
    invisible here, and an action taken after reading hostile content is labelled by it
    whether or not that content had anything to do with the action.
    """

    name: str = "tekmor"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        if not permitted_tool(action.tool, policy):
            return Decision(Verdict.BLOCK, ("TOOL_NOT_PERMITTED",))

        if not permitted_flow(
            action.tool,
            provenance.confidential,
            recipients_of(action.args, policy),
            policy,
        ):
            # The recipient itself is left out of the reason codes: they are public, and
            # a destination is part of what the run is trying to keep in.
            return Decision(
                Verdict.BLOCK,
                ("CONFIDENTIAL_INFLUENCE", "OUTBOUND_TOOL", "RECIPIENT_NOT_AUTHORIZED"),
            )

        if not trusted_action(action.tool, provenance.integrity, policy):
            violation = ("TARGET_TOOL_SENSITIVE", "ACTION_INTEGRITY_BELOW_THRESHOLD")
            downgrade = downgrade_for(action.tool, policy)
            if downgrade is None:
                return Decision(Verdict.ESCALATE, (*violation, "NO_CAPABILITY_DOWNGRADE"))
            # Arguments travel unchanged: the downgrade is of the *capability*, and the
            # variant is chosen to accept the same call. Argument redaction is a separate
            # rewrite that does not exist yet.
            return Decision(
                Verdict.REWRITE,
                (*violation, "CAPABILITY_DOWNGRADE"),
                Action(downgrade, action.args),
            )

        return Decision(
            Verdict.ALLOW,
            ("TOOL_PERMITTED", "PERMITTED_FLOW_SATISFIED", "TRUSTED_ACTION_SATISFIED"),
        )
