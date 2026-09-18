"""Tekmor defense component: the decision contract, the monitor, and the baselines.

`ReferenceMonitor` is the deterministic core of Proposal A: least privilege,
Permitted-Flow, then Trusted-Action with a capability downgrade. Signal extraction and
calibrated risk scoring are still Phase 3; see src/CLAUDE.md.
"""

from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Defense,
    Source,
    Verdict,
    mediate,
)
from tekmor.defense.monitor import ReferenceMonitor

__all__ = [
    "Action",
    "ActionProvenance",
    "AgentState",
    "Decision",
    "Defense",
    "ReferenceMonitor",
    "Source",
    "Verdict",
    "mediate",
]
