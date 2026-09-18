"""Tekmor observability component: the event schema and the append-only JSONL log.

The timeline and provenance-graph viewers are Phase 3; see src/CLAUDE.md.
"""

from tekmor.observability.events import DecisionEvent, EventLog, decision_event

__all__ = ["DecisionEvent", "EventLog", "decision_event"]
