"""Taint propagation: what the agent has read, and therefore what drove its next action.

`docs/technical-doc.md` Part I and `provenance/CLAUDE.md`: an action's integrity is the
minimum integrity of everything that influenced it. This module computes that set
instead of taking the scenario author's word for it, which is what turns the monitor's
verdicts into evidence about a *system* rather than about hand-declared labels.

The model is the agent's context: an observation the agent has seen is an influence on
every action it proposes afterwards, and it cannot unsee it. So the set only ever grows
within a run, which is also the rule "trust never increases through a round trip through
memory" — a summarised or re-serialized copy of a hostile document is still downstream
of the read that produced it.

ponytail: influence is call-level and prefix-monotone, not field-level. Every observation
the agent has seen taints every later action, so a benign action taken after reading one
hostile document is labelled by that document. That is the conservative direction, and
over-tainting is a real cost (`provenance/CLAUDE.md`): the benign halves of the scenario
pairs are the check on it. Upgrade path when it costs utility: field-level provenance on
tool results, and attributing an argument to the observation it was copied from.
"""

from __future__ import annotations

from dataclasses import dataclass

from tekmor.provenance.trust import Source, TrustLevel

#: The task itself. It comes from the person who asked for the work, so it is the one
#: influence present before the agent has read anything.
USER_REQUEST = Source("user:request", TrustLevel.AUTHENTICATED_USER, origin="user")


@dataclass(slots=True)
class TaintTracker:
    """The influences accumulated over one run. One tracker per run, never shared.

    Deduplicated by identity of the `Source`, so reading the same document twice is one
    influence, and kept in the order observed so a trace reads as the run happened.
    """

    sources: tuple[Source, ...] = (USER_REQUEST,)

    def observe(self, source: Source) -> None:
        """Record that the agent has seen `source`. Influence is never removed."""
        if source not in self.sources:
            self.sources = (*self.sources, source)
