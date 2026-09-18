"""Baseline defenses: the reference points every later number is read against.

`evaluation/CLAUDE.md`: a number without a baseline says nothing. These three bracket
the space — allow-all gives the utility ceiling and the security floor, deny-sensitive
the reverse, and the keyword filter stands in for the text-matching defenses that the
literature reports adaptive attackers bypassing (`docs/technical-doc.md` Part II).

None of them is a defense. They exist to be beaten.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Verdict,
)
from tekmor.policy.core import Policy

#: Words a naive filter would flag in an outbound argument. Deliberately shallow: the
#: point of this baseline is that shallow matching loses to encoding and paraphrase.
DEFAULT_KEYWORDS = frozenset(
    {
        "api key",
        "api_key",
        "credential",
        "ignore previous instructions",
        "password",
        "secret",
        "token",
    }
)


@dataclass(frozen=True, slots=True)
class AllowAll:
    """Undefended agent. Utility ceiling, security floor."""

    name: str = "allow-all"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        return Decision(Verdict.ALLOW, ("BASELINE_ALLOW_ALL",))


@dataclass(frozen=True, slots=True)
class DenySensitive:
    """Blocks every sensitive tool, whatever drove it.

    Secure by construction and useless by construction: it is the false-block rate a
    provenance-aware defense has to beat while keeping the same attack coverage.
    """

    name: str = "deny-sensitive"

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        if action.tool in policy.sensitive_tools:
            return Decision(Verdict.BLOCK, ("TARGET_TOOL_SENSITIVE",))
        return Decision(Verdict.ALLOW, ("TARGET_TOOL_NOT_SENSITIVE",))


@dataclass(frozen=True, slots=True)
class KeywordFilter:
    """Blocks an action whose arguments contain a flagged word.

    A strawman, and a specific one: it inspects the candidate action's arguments as
    text, so base64/hex/spaced/reversed encodings of the same value pass it, and benign
    work that merely mentions a flagged word is blocked. Both failures are measured
    rather than asserted; see tests/security/test_baselines.py.
    """

    name: str = "keyword"
    keywords: frozenset[str] = field(default=DEFAULT_KEYWORDS)

    def decide(
        self,
        state: AgentState,
        action: Action,
        provenance: ActionProvenance,
        policy: Policy,
    ) -> Decision:
        # ponytail: str() of the args covers nested values in one pass; a real scanner
        # walks fields so it can report which one matched.
        haystack = str(dict(action.args)).lower()
        if any(word in haystack for word in self.keywords):
            # The matched word is left out of the reason code on purpose: reason codes
            # are public, and the match may be a secret value.
            return Decision(Verdict.BLOCK, ("KEYWORD_MATCH",))
        return Decision(Verdict.ALLOW, ("NO_KEYWORD_MATCH",))
