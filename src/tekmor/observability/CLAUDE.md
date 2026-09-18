# CLAUDE.md — src/tekmor/observability/

Scope: the event schema, append-only event log, security timeline, and provenance graph.
Root and `src/` rules apply.

## Status

`events.py` is the schema and the log, at **version 2**: an event carries the decision,
its labelled source set, and what the gateway did with the action. `viewer.py` renders a
log as one self-contained HTML page — a timeline table per run and an inline-SVG
provenance graph — and reads the JSONL and nothing else. No charting dependency, no trace
backend, no script in the page.

Still missing from the schema in Part V: the agent-state summary, per-field provenance
within an observation, and the confidence beside the risk score. Each is missing because
the component that would produce it does not exist yet, which is the only acceptable
reason for a field to be absent.

## Trace completeness

A trace must allow a reader to reconstruct, without reading code:

```
agent state → candidate action → action provenance → policy/context →
risk/security decision → allow/block/escalate/rewrite → execution → outcome
```

Per `docs/technical-doc.md` Part V, an event carries: timestamp, run/seed, task ID, step
index, agent state summary, observation + source + assigned trust + sensitivity,
retrieved results with per-field provenance, candidate action (tool + args), the
influencing-observation set (taint sources), active policy ID, per-signal risk
contributions, aggregate risk + confidence, decision + reason codes, rewritten action if
any, outcome, side effects, and canary status.

## Rules

- **The log is append-only.** Events are never edited or deleted after the fact.
  Corrections are new events.
- **Every decided action produces exactly one event**, written after the gateway has
  acted so that one line carries the decision *and* its outcome. The alternative — a
  decision event and a separate outcome event joined on (run, step) — was rejected in
  `docs/decisions.md`: it buys the same completeness for a join in every reader.
- **The trace must be sufficient for the viewer.** If a view needs a fact the log does
  not carry, the fix is a schema field, never a second input to the renderer. A viewer
  that reads the scenario or the world would be a scorer, and its output would stop being
  evidence about what the trace can show.
- **A reader escapes everything it interpolates.** Tool names, source ids and origins
  derive from adversary-controlled content, so a rendered trace is a trust boundary.
- **Never log secrets, credentials, or canary values.** Log their *identity and flow*
  (which canary, which field, which sink) — never the value. Redaction is the schema's
  job, not the caller's discretion. This is why `outcome` is one of three words rather
  than the tool's result or its error message.
- **Provenance is logged per source, not only as its meet.** `integrity` is what the
  decision was computed from and stays; `sources` says which read dragged it there. A
  reader that meets an event with no labels represents that as `UNKNOWN` rather than
  choosing a level for it.
- Public/coarse reason codes and private fine-grained sub-scores are distinct fields, so
  an external view can be produced without leaking the attacker's hill-climbing signal.
- Serving two purposes at once — debugging the system, and evaluating the security
  mechanism — is deliberate. Do not drop a field just because the UI does not show it.
- OpenTelemetry GenAI / OpenInference conventions do not model trust, provenance chains,
  or decision reason codes. Extend them with `tekmor.*` attributes rather than bending a
  Tekmor concept into an ill-fitting standard attribute.
- The schema is versioned, and `schema_version` is on every event. A breaking change
  bumps `SCHEMA_VERSION` and updates the readers in the same PR; a reader that can still
  render an older shape does so explicitly, by branching on the version.
