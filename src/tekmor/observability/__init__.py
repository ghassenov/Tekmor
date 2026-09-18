"""Tekmor observability component: the event schema and the append-only JSONL log.

The timeline and provenance-graph viewers are Phase 3; see src/CLAUDE.md.
"""

from tekmor.observability.events import (
    SCHEMA_VERSION,
    DecisionEvent,
    EventLog,
    Outcome,
    decision_event,
    read,
)

__all__ = [
    "SCHEMA_VERSION",
    "DecisionEvent",
    "EventLog",
    "Outcome",
    "decision_event",
    "read",
]
