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

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from tekmor.provenance.trust import ENDORSED, Source, TrustLevel

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


#: The shortest argument value that counts as naming something. Below it a value is a
#: word the request may contain by accident ("pay", "all") rather than a resource name.
MIN_NAME = 6


def endorse(source: Source, args: Mapping[str, Any], request: str) -> Source:
    """`source`, endorsed by the user if the call that produced it named what they named.

    The endorsement primitive `docs/technical-doc.md` Recommendation 1 asks for once
    utility falls: when the user's authenticated request names a resource verbatim ("pay
    the bill in `bill-december-2023.txt`") and the agent reads exactly that resource, the
    user has vouched for acting on it, and content that was merely *unvouched for* may
    drive the action they asked for. It is a provenance link, not a text classifier:
    what is compared is the read's own argument against the request, never the content.

    It is deliberately narrow. Only `UNTRUSTED_*` content is endorsed — content the
    organization already knows is hostile stays `ADVERSARY_CONTROLLED` whoever names it,
    and trusted content needs nothing. Only integrity moves: confidentiality is
    untouched, so an endorsed read of a secret still may not leave (Permitted-Flow).

    ponytail: "named" is a verbatim match of an argument value of at least `MIN_NAME`
    characters. An attacker who can create a resource whose name is a phrase in the
    request borrows the endorsement for it. The upgrade is structured endorsement — the
    user attaching the resource — which needs an interface this repository does not have.
    """
    if not TrustLevel.UNTRUSTED_EXTERNAL <= source.trust < ENDORSED:
        return source
    named = any(
        isinstance(value, str) and len(value) >= MIN_NAME and value in request
        for value in args.values()
    )
    return replace(source, endorsed_by=USER_REQUEST.id) if named else source
