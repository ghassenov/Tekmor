# CLAUDE.md — src/tekmor/runtime/

Scope: the model adapter, the run loop, and the tool gateway. Root and `src/` rules
apply.

## Status

**Implemented:** `model.py` (the `ModelAdapter` protocol and the deterministic
`ScriptedModel`), `runner.py` (the run loop, the gateway call, the simulated approver).

**Not implemented:** the Qwen3-8B adapter (Transformers, with residual-stream hooks left
reachable for Proposal C) and anything that reacts to a verdict.

## Rules

- **`world.invoke` has exactly one call site**, in `runner.run`, reached only after
  `mediate()` returned a verdict that permits it. Complete mediation is a property you
  should be able to confirm by reading that function; adding a second path to the world
  destroys it.
- **Unrecognised verdict executes nothing.** `_approved` returns `None` by default, so a
  verdict added later fails closed until it is handled on purpose.
- **ESCALATE denies by default.** A run that wants approvals passes an `Approver`; a run
  that forgets does not silently get ALLOW.
- **The adapter never sees the verdict**, only the observation that follows it. An
  adapter that could read decisions would be able to probe the monitor for free.
- **`AgentState` carries the task and the step index only.** Do not add scenario
  identifiers, expected outcomes, or anything else a defense could recognise.
- Every decision is logged when a log is given, before the action executes.
- Tests use `ScriptedModel`. Anything needing a real backend is marked `slow`.
