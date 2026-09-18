# CLAUDE.md — src/tekmor/observability/

Scope: the event schema, append-only event log, security timeline, and provenance graph.
Root and `src/` rules apply.

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
- **Every decision produces exactly one decision event**, and every action/outcome pair is
  correlated by stable IDs (run, step, action) so the timeline and provenance graph can be
  rebuilt from the log alone.
- **Never log secrets, credentials, or canary values.** Log their *identity and flow*
  (which canary, which field, which sink) — never the value. Redaction is the schema's
  job, not the caller's discretion.
- Public/coarse reason codes and private fine-grained sub-scores are distinct fields, so
  an external view can be produced without leaking the attacker's hill-climbing signal.
- Serving two purposes at once — debugging the system, and evaluating the security
  mechanism — is deliberate. Do not drop a field just because the UI does not show it.
- OpenTelemetry GenAI / OpenInference conventions do not model trust, provenance chains,
  or decision reason codes. Extend them with `tekmor.*` attributes rather than bending a
  Tekmor concept into an ill-fitting standard attribute.
- The schema is versioned. A breaking change bumps the version and updates the evaluation
  readers in the same PR.
