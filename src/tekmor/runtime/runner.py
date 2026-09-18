"""The run loop, and the gateway that is the world's only door.

`docs/technical-doc.md` Part I: scenario + world + policy → runner → the agent proposes
an action → Tekmor decides → escalations go to a simulated human, approved actions go
to the tool gateway → world state updates → events are logged.

The gateway is not a class. It is the single `world.invoke` call below, reached only
after `mediate()` returned a verdict that permits it — one call site is what makes
"nothing reaches the world undecided" checkable by reading the function.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tekmor.defense import Action, ActionProvenance, AgentState, Decision, Defense, Verdict
from tekmor.defense.core import mediate
from tekmor.observability import EventLog, decision_event
from tekmor.runtime.model import ModelAdapter, ScriptedModel
from tekmor.simulator.scenario import Scenario
from tekmor.simulator.world import World

#: The simulated human an ESCALATE goes to. Denying is the safe default, and a run that
#: needs approvals says so by passing its own.
Approver = Callable[[Action], bool]


def deny(action: Action) -> bool:
    return False


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """What happened to one proposed action, decision included."""

    action: Action
    decision: Decision
    executed: Action | None
    result: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    scenario_id: str
    defense: str
    steps: tuple[StepOutcome, ...]
    world: World


def _approved(decision: Decision, action: Action, approver: Approver) -> Action | None:
    """The action to execute, or `None`. Anything unrecognised executes nothing."""
    if decision.verdict is Verdict.ALLOW:
        return action
    if decision.verdict is Verdict.REWRITE:
        return decision.rewritten
    if decision.verdict is Verdict.ESCALATE and approver(action):
        return action
    return None


def run(
    scenario: Scenario,
    defense: Defense,
    *,
    adapter: ModelAdapter | None = None,
    log: EventLog | None = None,
    run_id: str | None = None,
    approver: Approver = deny,
    max_steps: int = 64,
) -> RunResult:
    """Run one scenario against one defense and return what the world looks like after.

    `run_id` defaults to scenario and defense, so a rerun of the same pair is the same
    identifier: with a scripted adapter the whole run is deterministic, and two runs
    that differ differ because the defense did.
    """
    world = scenario.world()
    adapter = adapter or ScriptedModel(scenario.steps)
    run_id = run_id or f"{scenario.id}@{scenario.version}:{defense.name}"

    observations: list[str] = []
    outcomes: list[StepOutcome] = []

    for step in range(max_steps):
        # The state deliberately carries the task and the step index and nothing else:
        # no scenario id, no expected outcome, nothing a defense could recognise.
        state = AgentState(task=scenario.task, step=step)
        proposal = adapter.propose(state, tuple(observations))
        if proposal is None:
            break

        provenance = ActionProvenance.of(proposal.sources)
        decision = mediate(defense, state, proposal.action, provenance, scenario.policy)
        if log is not None:
            log.append(
                decision_event(run_id, step, defense.name, proposal.action, provenance, decision)
            )

        executed = _approved(decision, proposal.action, approver)
        result = error = None
        if executed is not None:
            try:
                result = world.invoke(executed.tool, executed.args)
            except Exception as exc:  # a bad call is an outcome, not a crashed run
                error = f"{type(exc).__name__}: {exc}"
        outcomes.append(StepOutcome(proposal.action, decision, executed, result, error))
        observations.append(result or error or decision.verdict.value)

    return RunResult(run_id, scenario.id, defense.name, tuple(outcomes), world)
