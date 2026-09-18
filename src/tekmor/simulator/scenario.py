"""The scenario format: one run's world, policy, and scripted agent steps.

Scenarios are JSON or YAML: both front ends produce the same `Scenario`, and the
validation below is the only definition of the format. JSON needs nothing; YAML needs
PyYAML, which is an optional extra rather than a runtime dependency, so a checkout that
never touches a `.yaml` scenario still installs nothing. See `docs/decisions.md`.

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
    return Source(
        id=_require(data, "id", str),
        trust=trust,
        origin=str(data.get("origin", "")),
        confidential=bool(data.get("confidential", False)),
    )


def _policy(data: Mapping[str, Any], outbound: frozenset[str]) -> Policy:
    """Build the policy, defaulting `outbound_tools` to the domain's own outbound tools.

    Where a tool sends data is a property of the tool, so a scenario that restated it
    could disagree with the world it runs against. The default comes from the domain's
    tool specs; a scenario may still state the set explicitly, which is how a policy that
    treats an extra tool as outbound gets written.
    """
    level = data.get("min_integrity", "TRUSTED_INTERNAL")
    try:
        min_integrity = TrustLevel[level]
    except (KeyError, TypeError):
        raise ScenarioError(f"unknown trust level {level!r}") from None
    return Policy(
        name=_require(data, "name", str),
        sensitive_tools=frozenset(data.get("sensitive_tools", ())),
        allowed_tools=frozenset(data.get("allowed_tools", ())),
        outbound_tools=frozenset(data.get("outbound_tools", outbound)),
        min_integrity=min_integrity,
        authorized_recipients=frozenset(data.get("authorized_recipients", ())),
        recipient_args=frozenset(data.get("recipient_args", ("to",))),
        rewrites=dict(data.get("rewrites", {})),
        version=_require(data, "version", int) if "version" in data else 1,
    )


def parse_scenario(data: Mapping[str, Any]) -> Scenario:
    """Build a scenario from already-parsed JSON, validating as we go.

    Scenario files are an input the rest of the system trusts, so a malformed one fails
    here with a message rather than somewhere in the middle of a run.
    """
    domain = _require(data, "domain", str)
    if domain not in DOMAINS:
        raise ScenarioError(f"unknown domain {domain!r}; have {sorted(DOMAINS)}")
    tools = {tool.name for tool in DOMAINS[domain]}
    outbound = frozenset(tool.name for tool in DOMAINS[domain] if tool.outbound)

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

    policy = _policy(_require(data, "policy", dict), outbound)
    named = (
        policy.sensitive_tools
        | policy.allowed_tools
        | policy.outbound_tools
        | set(policy.rewrites)
        | set(policy.rewrites.values())
    )
    # A typo in a policy is silent otherwise: an unknown name in `allowed_tools` blocks
    # work, and one in `sensitive_tools` un-guards a tool that was meant to be guarded.
    if named - tools:
        raise ScenarioError(f"policy names {sorted(named - tools)}, not tools of domain {domain!r}")

    return Scenario(
        id=_require(data, "id", str),
        version=_require(data, "version", int),
        domain=domain,
        task=_require(data, "task", str),
        benign=_require(data, "benign", bool),
        policy=policy,
        documents=dict(data.get("documents", {})),
        canaries=dict(data.get("canaries", {})),
        steps=tuple(steps),
    )


def load_scenario(path: str | Path) -> Scenario:
    """Load a scenario from a `.json`, `.yaml` or `.yml` file."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ModuleNotFoundError:
            raise ScenarioError(
                f"{path.name} is YAML, which needs PyYAML: uv sync --extra yaml"
            ) from None
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, Mapping):
        raise ScenarioError(f"{path.name} is not a scenario object")
    return parse_scenario(data)
