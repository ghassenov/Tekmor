"""The scenario format: one run's world, policy, and scripted agent steps.

Scenarios are JSON. `docs/technical-doc.md` says YAML, but YAML needs a dependency and
the format is a handful of lists and strings; the deviation is recorded in
`docs/decisions.md`.

A scenario carries metadata the *scorer* needs (`id`, `version`, `benign`) and content
the *run* needs (world, policy, steps). Only the second group ever reaches the defense:
a defense that can read `id` or `benign` can recognise its test cases, which is the one
thing that would make every later number meaningless.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tekmor.policy.core import Policy
from tekmor.provenance.trust import Source, TrustLevel
from tekmor.simulator.domains import DOMAINS
from tekmor.simulator.world import World


class ScenarioError(ValueError):
    """A scenario file is missing something or names something that does not exist."""


@dataclass(frozen=True, slots=True)
class ScriptedStep:
    """One action the scripted agent proposes, with the sources that influenced it.

    Declaring the influencing sources is a Phase 1 stand-in: taint propagation computes
    them from what the agent actually read (Phase 2). Until then the scenario author
    states them, which keeps the decision core testable without pretending the
    propagation exists.
    """

    tool: str
    args: Mapping[str, Any]
    sources: tuple[Source, ...]


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    version: int
    domain: str
    task: str
    benign: bool
    policy: Policy
    documents: Mapping[str, str]
    canaries: Mapping[str, str]
    steps: tuple[ScriptedStep, ...]

    def world(self) -> World:
        """A fresh world for one run. Runs never share mutable state."""
        return World.build(DOMAINS[self.domain], self.documents, self.canaries)


def _require(data: Mapping[str, Any], key: str, kind: type) -> Any:
    value = data.get(key)
    if not isinstance(value, kind):
        raise ScenarioError(f"scenario field {key!r} must be {kind.__name__}, got {value!r}")
    return value


def _source(data: Mapping[str, Any]) -> Source:
    name = _require(data, "trust", str)
    try:
        trust = TrustLevel[name]
    except KeyError:
        raise ScenarioError(f"unknown trust level {name!r}") from None
    return Source(id=_require(data, "id", str), trust=trust, origin=str(data.get("origin", "")))


def parse_scenario(data: Mapping[str, Any]) -> Scenario:
    """Build a scenario from already-parsed JSON, validating as we go.

    Scenario files are an input the rest of the system trusts, so a malformed one fails
    here with a message rather than somewhere in the middle of a run.
    """
    domain = _require(data, "domain", str)
    if domain not in DOMAINS:
        raise ScenarioError(f"unknown domain {domain!r}; have {sorted(DOMAINS)}")
    tools = {tool.name for tool in DOMAINS[domain]}

    steps = []
    for raw in _require(data, "steps", list):
        tool = _require(raw, "tool", str)
        if tool not in tools:
            raise ScenarioError(f"step calls {tool!r}, not a tool of domain {domain!r}")
        steps.append(
            ScriptedStep(
                tool=tool,
                args=dict(_require(raw, "args", dict)),
                sources=tuple(_source(s) for s in _require(raw, "sources", list)),
            )
        )

    policy = _require(data, "policy", dict)
    return Scenario(
        id=_require(data, "id", str),
        version=_require(data, "version", int),
        domain=domain,
        task=_require(data, "task", str),
        benign=_require(data, "benign", bool),
        policy=Policy(
            name=_require(policy, "name", str),
            sensitive_tools=frozenset(policy.get("sensitive_tools", ())),
        ),
        documents=dict(data.get("documents", {})),
        canaries=dict(data.get("canaries", {})),
        steps=tuple(steps),
    )


def load_scenario(path: str | Path) -> Scenario:
    return parse_scenario(json.loads(Path(path).read_text(encoding="utf-8")))
