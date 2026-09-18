"""The `ModelAdapter` interface and the deterministic mock behind every test.

`docs/technical-doc.md` Part I: a mock model for fast deterministic tests, and a
Qwen3-8B backend for real runs. The Qwen3-8B adapter lives in `qwen.py`, behind an
optional extra; this module is the interface and the mock every test uses.

An adapter proposes actions. It never decides anything: the decision is `mediate()`'s,
and an adapter cannot see the verdict except through the observation it gets back.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tekmor.defense import Action, AgentState
from tekmor.provenance.trust import Source
from tekmor.simulator.scenario import ScriptedStep


@dataclass(frozen=True, slots=True)
class Proposal:
    """A candidate action and the sources that influenced it.

    Phase 2 replaces the declared `sources` with taint computed from what the agent
    actually read; the field stays, its provider changes.
    """

    action: Action
    sources: tuple[Source, ...] = ()


@runtime_checkable
class ModelAdapter(Protocol):
    """Anything that can propose the next action, or `None` when the task is done."""

    name: str

    def propose(self, state: AgentState, observations: Sequence[str]) -> Proposal | None: ...


@dataclass(frozen=True, slots=True)
class ScriptedModel:
    """Replays a scenario's scripted steps, ignoring observations.

    Deterministic by construction, which is what makes a run reproducible and what lets
    a security test assert on the defense rather than on model behaviour. The cost is
    that it does not react to a block — so it measures what the monitor stops, never
    whether a real agent would recover.
    """

    steps: tuple[ScriptedStep, ...]
    name: str = "scripted"

    def propose(self, state: AgentState, observations: Sequence[str]) -> Proposal | None:
        if state.step >= len(self.steps):
            return None
        step = self.steps[state.step]
        return Proposal(Action(step.tool, step.args), step.sources)
