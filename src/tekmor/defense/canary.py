"""CANARY-FLOW: the argument-level residual, checked against the secret registry.

`docs/technical-doc.md` mechanism 8. `ReferenceMonitor` decides from *provenance*: a
confidential value is one the run read through a labelled source, which is why every
encoding of it is refused for the same reason and why no encoding list ever has to be
complete. The residual, recorded in `docs/decisions.md`, is the other direction — a
secret that reaches an argument without passing through a labelled observation is
invisible to that rule, because nothing in the run ever said it was confidential. A
mislabelled wiki page with a token pasted into it is the ordinary way that happens, and
it needs no attacker sophistication at all.

This wraps a defense and closes that residual by scanning the outbound call's arguments
for known secrets in any encoding `tekmor.provenance.canary` recognises. It is
deliberately *layered* rather than folded into the monitor:

- the monitor's claim is that it never reads argument text, and that claim is what makes
  its verdicts encoding-independent. Mixing a text matcher into it would retire the
  claim for every decision, including the ones that never needed the matcher;
- Phase 4 ablations need to run the core with and without this, which a wrapper gives
  for free and an inlined check does not;
- it is a text matcher, and the literature this project is built on is about text
  matchers being bypassed. Keeping it visibly separate keeps it from being mistaken for
  the defense.

**Monotone-safe fusion** (`defense/CLAUDE.md` invariant 4): this only ever *raises*
suspicion. A BLOCK from the wrapped defense is returned untouched, and the scanner's own
answer can turn ALLOW or REWRITE into BLOCK but never the reverse. The same holds for
the reported risk score, which is raised to this layer's own severity and never lowered
below what the wrapped defense scored.

**It scans arguments, so it sees only what the call itself carries.** In the financial
domain what leaves is the *prepared payment*, staged by an earlier non-outbound call, and
`execute_payment` takes only an id — so a canary routed through payment state is a leak
this layer does not see and `World.canaries_in` does (it reads the payment). That is not
an oversight to fix here: scanning state rather than arguments is a different mechanism,
and the rule that does cover it is the provenance one, which labels the action from the
read that produced the value. Recorded in `tests/security/test_canary_scanner.py`.

**The secret registry is a deployment input, not scenario metadata.** It is the
organization's own list of what must not leave — the DLP analogue — and it carries no
scenario id, no `benign` flag and nothing else a defense could recognise a test case by
(`src/CLAUDE.md`). Deriving it from anything that does would void every number measured
with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Defense,
    Verdict,
    mediate,
)
from tekmor.defense.risk import SEVERITY
from tekmor.policy.core import Policy, permitted_flow, recipients_of
from tekmor.provenance.canary import appears_in

#: A registered secret found in the argument of a call heading somewhere unauthorized.
#: Scored as the flow violation it is an instance of (`defense/risk.py`) rather than at
#: the top of the scale: what this layer adds is *evidence* of that violation where the
#: labels carried none, not a worse violation than the one the rule already names.
CANARY_SEVERITY = SEVERITY["CONFIDENTIAL_INFLUENCE"]


@dataclass(frozen=True, slots=True)
class CanaryScanner:
    """A defense, plus a scan of what the approved call would actually carry out."""

    inner: Defense
    #: The values that must not leave. Never logged, never named in a reason code.
    secrets: frozenset[str] = field(default_factory=frozenset)

    @property
    def name(self) -> str:
        """Names the layer *and* what it wraps.

        The defense name is what a run id and every event line is keyed by, so two
        different defenses must not share one: `canary` over the monitor and `canary`
        over `AllowAll` are different mechanisms with very different results, and an
        ablation table that could not tell them apart would be wrong rather than coarse.
        """
        return f"{self.inner.name}+canary"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        # Through `mediate`, so a wrapped defense that raises fails closed here exactly
        # as it would at the top level, rather than taking this one down with it.
        decision = mediate(self.inner, state, action, provenance, policy)
        if decision.verdict is Verdict.BLOCK:
            return decision

        # The call that would *execute*, which after a capability downgrade is not the
        # one proposed: a canary in a `draft_email` body is not a canary leaving.
        outgoing = decision.rewritten or action
        # Asking Permitted-Flow the question with `confidential=True` is asking "would
        # this destination be allowed to receive a secret?". If the policy says yes, a
        # secret going there is authorized work and blocking it is a false block. It
        # also answers yes for any non-outbound tool, which is the check for that.
        if permitted_flow(outgoing.tool, True, recipients_of(outgoing.args, policy), policy):
            return decision

        if not any(
            appears_in(secret, str(value))
            for secret in self.secrets
            for value in outgoing.args.values()
        ):
            return decision

        # Which secret, and which argument, stay out of the public reason codes: the
        # first is close to the value and the second is a hill-climbing channel that
        # tells an attacker exactly which field was read (`defense/CLAUDE.md`).
        return Decision(
            Verdict.BLOCK,
            ("CANARY_IN_OUTBOUND_ARGUMENT", "RECIPIENT_NOT_AUTHORIZED"),
            risk=max(CANARY_SEVERITY, decision.risk or 0.0),
        )
