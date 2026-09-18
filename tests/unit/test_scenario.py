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
    "documents": {"INV-1": {"text": "4 200 EUR", "trust": "TRUSTED_INTERNAL"}},
    "steps": [{"tool": "send_email", "args": {"to": "a@example.com"}}],
}


def test_parses_document_labels_into_trust_levels():
    scenario = parse_scenario(MINIMAL)
    assert scenario.documents["INV-1"].trust is TrustLevel.TRUSTED_INTERNAL
    assert scenario.policy.sensitive_tools == frozenset({"send_email"})


def test_outbound_tools_come_from_the_domain_not_from_the_scenario():
    # Where a tool sends data is a property of the tool. A scenario that restated it
    # could disagree with the world it runs against, so the default is the domain's own
    # tool specs.
    assert parse_scenario(MINIMAL).policy.outbound_tools == frozenset({"send_email"})


def test_a_document_may_be_labelled_confidential():
    documents = {"INV-1": {**MINIMAL["documents"]["INV-1"], "confidential": True}}
    scenario = parse_scenario({**MINIMAL, "documents": documents})
    assert scenario.documents["INV-1"].confidential is True
    # And it is off unless the scenario says so: labelling everything confidential would
    # block every outbound call.
    assert parse_scenario(MINIMAL).documents["INV-1"].confidential is False


def test_loaded_scenario_has_the_expected_shape(attack_scenario):
    assert attack_scenario.benign is False
    assert [step.tool for step in attack_scenario.steps] == [
        "read_document",
        "read_secret",
        "send_email",
    ]
    assert attack_scenario.documents["INV-91"].trust is TrustLevel.ADVERSARY_CONTROLLED


@pytest.mark.parametrize(
    "change",
    [
        {"domain": "trading_floor"},
        {"steps": [{**MINIMAL["steps"][0], "tool": "wire_transfer"}]},
        {"documents": {"INV-1": {"text": "x", "trust": "SEMI_TRUSTED"}}},
        {"documents": {"INV-1": "an unlabelled document"}},
        {"steps": [{**MINIMAL["steps"][0], "sources": [{"id": "x", "trust": "TRUSTED_INTERNAL"}]}]},
        {"version": "1"},
        {"benign": "yes"},
        {"policy": {**MINIMAL["policy"], "allowed_tools": ["send_emails"]}},
        {"policy": {**MINIMAL["policy"], "rewrites": {"send_email": "draff_email"}}},
        {"policy": {**MINIMAL["policy"], "min_integrity": "SEMI_TRUSTED"}},
    ],
    ids=[
        "unknown domain",
        "tool not in domain",
        "unknown trust",
        # Guessing a label is the one thing the loader must not do: too high invents
        # trust, too low turns every scenario into an attack.
        "unlabelled document",
        # A stale scenario would otherwise keep passing with its labels ignored.
        "step declares its own sources",
        "bad version",
        "bad benign",
        # A typo in a policy is silent otherwise: an unknown name in `allowed_tools`
        # blocks work, and one in `rewrites` quietly removes the downgrade.
        "policy names a tool the domain does not have",
        "rewrite target not in the domain",
        "unknown integrity threshold",
    ],
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


def test_a_yaml_scenario_loads(scenario):
    soc = scenario("soc_injection_alert.yaml")
    assert soc.domain == "soc"
    assert [step.tool for step in soc.steps] == [
        "read_alert",
        "read_secret",
        "share_indicators",
        "isolate_host",
    ]
    assert soc.documents["ALERT-4"].trust is TrustLevel.ADVERSARY_CONTROLLED
