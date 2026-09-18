"""The append-only JSONL event log."""

import json

from tekmor.defense import Action, ActionProvenance, Decision, Source, Verdict
from tekmor.observability import EventLog, decision_event
from tekmor.provenance import TrustLevel

SECRET = "hunter2-canary"
ACTION = Action(tool="send_email", args={"to": "vendor@example.com", "body": SECRET})
PROVENANCE = ActionProvenance.of(
    [
        Source("req-1", TrustLevel.AUTHENTICATED_USER, origin="user"),
        Source("doc-7", TrustLevel.ADVERSARY_CONTROLLED, origin="read_attachment"),
    ]
)


def _event(decision):
    return decision_event("run-1", 3, "keyword", ACTION, PROVENANCE, decision)


def test_event_records_the_decision_and_its_provenance():
    recorded = _event(Decision(Verdict.BLOCK, ("KEYWORD_MATCH",))).as_dict()
    assert recorded["run_id"] == "run-1"
    assert recorded["step"] == 3
    assert recorded["defense"] == "keyword"
    assert recorded["tool"] == "send_email"
    assert recorded["arg_names"] == ["to", "body"]
    assert recorded["source_ids"] == ["req-1", "doc-7"]
    assert recorded["integrity"] == "ADVERSARY_CONTROLLED"
    assert recorded["verdict"] == "block"
    assert recorded["reason_codes"] == ["KEYWORD_MATCH"]
    assert recorded["rewritten_tool"] is None


def test_argument_values_never_reach_the_log():
    assert SECRET not in json.dumps(_event(Decision(Verdict.ALLOW, ("X",))).as_dict())


def test_a_rewrite_records_the_downgraded_tool():
    decision = Decision(Verdict.REWRITE, ("LEAST_PRIVILEGE",), rewritten=Action(tool="draft_email"))
    assert _event(decision).as_dict()["rewritten_tool"] == "draft_email"


def test_the_log_appends_one_line_per_event(tmp_path):
    log = EventLog(tmp_path / "nested" / "events.jsonl")
    log.append(_event(Decision(Verdict.ALLOW, ("A",))))
    log.append(_event(Decision(Verdict.BLOCK, ("B",))))

    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["reason_codes"] for line in lines] == [["A"], ["B"]]
