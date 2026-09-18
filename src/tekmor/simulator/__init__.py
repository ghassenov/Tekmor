"""Tekmor simulator component: the synthetic world, typed tools, and scenarios.

The scenario matrix and the robustness variants are later phases; see src/CLAUDE.md.
"""

from tekmor.simulator.domains import DOMAINS
from tekmor.simulator.scenario import Scenario, ScriptedStep, load_scenario
from tekmor.simulator.world import Tool, UnknownTool, World

__all__ = [
    "DOMAINS",
    "Scenario",
    "ScriptedStep",
    "Tool",
    "UnknownTool",
    "World",
    "load_scenario",
]
