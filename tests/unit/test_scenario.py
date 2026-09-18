"""The scenario format and its validation."""

import json

import pytest

from conftest import SCENARIOS
from tekmor.provenance import TrustLevel
from tekmor.simulator.scenario import ScenarioError, load_scenario, parse_scenario

MINIMAL = {
    "id": "s",
    "version": 1,
    "domain": "enterprise",
    "benign": True,
    "task": "t",
    "policy": {"name": "enterprise", "sensitive_tools": ["send_email"]},
    "steps": [
        {
            "tool": "send_email",
            "args": {"to": "a@example.com"},
            "sources": [{"id": "user:request", "trust": "AUTHENTICATED_USER"}],
        }
    ],
}


def test_parses_sources_into_trust_levels():
    scenario = parse_scenario(MINIMAL)
    assert scenario.steps[0].sources[0].trust is TrustLevel.AUTHENTICATED_USER
    assert scenario.policy.sensitive_tools == frozenset({"send_email"})


def test_loaded_scenario_has_the_expected_shape(attack_scenario):
    assert attack_scenario.benign is False
    assert [step.tool for step in attack_scenario.steps] == [
        "read_document",
        "read_secret",
        "send_email",
    ]
    assert attack_scenario.steps[1].sources[0].trust is TrustLevel.ADVERSARY_CONTROLLED


@pytest.mark.parametrize(
    "change",
    [
        {"domain": "trading_floor"},
        {"steps": [{**MINIMAL["steps"][0], "tool": "wire_transfer"}]},
        {"steps": [{**MINIMAL["steps"][0], "sources": [{"id": "x", "trust": "SEMI_TRUSTED"}]}]},
        {"version": "1"},
        {"benign": "yes"},
    ],
    ids=["unknown domain", "tool not in domain", "unknown trust", "bad version", "bad benign"],
)
def test_a_malformed_scenario_fails_on_load(change):
    # A scenario is an input the rest of the run trusts; it fails here, with a message,
    # rather than halfway through a run.
    with pytest.raises(ScenarioError):
        parse_scenario({**MINIMAL, **change})


def test_yaml_and_json_front_ends_produce_the_same_scenario(tmp_path, scenario):
    # The format is defined by parse_scenario, not by the file syntax: a YAML file and
    # the JSON it came from must load to the same object, or results recorded against
    # one representation stop being comparable with the other.
    yaml = pytest.importorskip("yaml")
    from_json = scenario("enterprise_injection_invoice.json")

    path = tmp_path / "same.yaml"
    path.write_text(
        yaml.safe_dump(json.loads((SCENARIOS / "enterprise_injection_invoice.json").read_text()))
    )
    assert load_scenario(path) == from_json

