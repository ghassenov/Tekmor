"""Risk scoring: one number per candidate action, from the signals the decision used.

`docs/technical-doc.md` Part IV stage 3 and Part VI. The deterministic rules already
answer *what to do*; a score answers *how bad this looked*, which the rules throw away.
Three things need it: the calibration metrics the evaluation design asks for
(precision/recall, AUROC, ECE — a verdict cannot be calibrated, only a score can), the
"ambiguous" band a secondary sensor would arbitrate (Proposal B), and a trace a reader
can sort.

**The score decides nothing, and that is the design.** `ReferenceMonitor` reaches its
verdict from the rules in their fixed order; the score is computed from the same
`Signals` object and reported alongside. A weighted sum that could *overrule* a rule
would replace a policy anyone can audit with weights nobody can, and the weights would
be tuned by the same person who writes the scenarios.

What the thresholds are for, then: `band()` is the doc's threshold table
(low→ALLOW, medium→REWRITE, ambiguous→ESCALATE, high→BLOCK) stated as a *falsifiable
claim about the rules* — for every action the monitor decides, `band(score(signals))`
must equal the verdict the rules produced. `tests/security/test_risk_bands.py` asserts
that over the whole scenario matrix, so the day a rule and the score disagree, a test
says so instead of a dashboard quietly showing risk 0.1 next to a BLOCK.

**Severities are ordinal, not probabilities.** `SEVERITY` orders the violations by how
much of the blast radius each one covers, and the score is the *worst* one that fired —
not a sum, because two independent violations do not make an action twice as dangerous,
and a sum would let several small signals outrank an exfiltration. Whether these
severities are *calibrated* (does 0.9 mean nine runs in ten are compromised?) is exactly
what ECE measures, and the answer for a hand-ordered scale is expected to be poor; the
number is reported rather than claimed (`evaluation/metrics.py`).
"""

from __future__ import annotations

from tekmor.defense.core import Verdict
from tekmor.defense.signals import Signals

#: Ordinal severity per violation, highest first. The names are the reason codes the
#: monitor emits, so a contribution can be read against the decision that cited it.
SEVERITY: dict[str, float] = {
    # Least privilege: a tool nobody granted. Nothing about the call can be judged.
    "TOOL_NOT_PERMITTED": 1.0,
    # Permitted-Flow: confidential influence heading to an unauthorized destination.
    # There is no safe downgrade of an exfiltration, so it sits above Trusted-Action.
    "CONFIDENTIAL_INFLUENCE": 0.9,
    # Trusted-Action with no vetted lower-capability variant: a human has to decide.
    "ACTION_INTEGRITY_BELOW_THRESHOLD": 0.7,
    # The same violation where the policy declares a downgrade: the blast radius is
    # bounded by the variant, and the user still gets the draft.
    "CAPABILITY_DOWNGRADE": 0.5,
    # Not violations. The agent read low-integrity or confidential content and the
    # action it drove is one the policy permits anyway — the gray zone, kept visible
    # because "untrusted is not irrelevant" cuts both ways.
    "UNTRUSTED_INFLUENCE": 0.1,
    "CONFIDENTIAL_INFLUENCE_PERMITTED": 0.1,
}

#: Band edges, each the midpoint between the two severities it separates: a score
#: strictly below the first band is ALLOW, and so on up. Midpoints rather than the
#: severities themselves so that a re-weighting has to move a severity *past* another
#: one before the band it lands in changes.
ALLOW_MAX = 0.25  # between the gray-zone signals (0.1) and a bounded downgrade (0.5)
REWRITE_MAX = 0.6  # between a bounded downgrade and one needing a human (0.7)
ESCALATE_MAX = 0.8  # between that and an unbounded flow or tool violation (0.9, 1.0)


def contributions(signals: Signals) -> tuple[tuple[str, float], ...]:
    """Every signal that fired, with its severity, worst first.

    The private half of the explanation (`defense/CLAUDE.md`): the monitor's public
    reason codes name the rule that decided, and these name everything that weighed on
    it. Keep them out of anything an attacker reads — a per-signal breakdown is a
    hill-climbing channel.
    """
    fired: list[tuple[str, float]] = []
    if not signals.tool_permitted:
        fired.append(("TOOL_NOT_PERMITTED", SEVERITY["TOOL_NOT_PERMITTED"]))
    if not signals.flow_permitted:
        fired.append(("CONFIDENTIAL_INFLUENCE", SEVERITY["CONFIDENTIAL_INFLUENCE"]))
    elif signals.confidential_influence:
        fired.append(
            ("CONFIDENTIAL_INFLUENCE_PERMITTED", SEVERITY["CONFIDENTIAL_INFLUENCE_PERMITTED"])
        )
    if not signals.integrity_sufficient:
        code = "CAPABILITY_DOWNGRADE" if signals.downgrade else "ACTION_INTEGRITY_BELOW_THRESHOLD"
        fired.append((code, SEVERITY[code]))
    elif signals.untrusted_influence:
        fired.append(("UNTRUSTED_INFLUENCE", SEVERITY["UNTRUSTED_INFLUENCE"]))
    return tuple(sorted(fired, key=lambda item: -item[1]))


def score(signals: Signals) -> float:
    """The worst severity that fired, in [0, 1]. A clean action scores 0."""
    fired = contributions(signals)
    return fired[0][1] if fired else 0.0


def band(risk: float) -> Verdict:
    """The verdict the thresholds map `risk` to (`docs/technical-doc.md` Part XIII).

    ESCALATE sits *above* REWRITE rather than beside it: both answer a Trusted-Action
    violation, and which one applies is whether a bounded variant exists. Deferring to a
    human is the more expensive answer, so it is the higher band.
    """
    if risk < ALLOW_MAX:
        return Verdict.ALLOW
    if risk < REWRITE_MAX:
        return Verdict.REWRITE
    if risk < ESCALATE_MAX:
        return Verdict.ESCALATE
    return Verdict.BLOCK
