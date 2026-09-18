"""Policy objects handed to `Defense.decide`.

Phase 1 carries only what the baselines need: which tools the domain considers
sensitive. The declarative per-domain rules (Trusted-Action, Permitted-Flow,
least-privilege) and their evaluation are Phase 2.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Policy:
    """The active policy for one domain.

    Tool sensitivity lives here rather than on a tool definition because it is a
    per-domain judgement: the same `send_email` tool is routine in one deployment and
    restricted in another. The simulator's tool specs will carry capability *variants*
    (for the rewriter); which of them count as sensitive stays policy.
    """

    name: str
    sensitive_tools: frozenset[str] = field(default_factory=frozenset)
