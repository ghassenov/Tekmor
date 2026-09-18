# CLAUDE.md — src/tekmor/runtime/

Scope: the model adapter, the run loop, and the tool gateway. Root and `src/` rules
apply.

## Status

**Implemented:** `model.py` (the `ModelAdapter` protocol and the deterministic
`ScriptedModel`), `gateway.py` (`ToolGateway`, the verdict handling and the simulated
approver), `runner.py` (the run loop), `qwen.py` (the Qwen3-8B adapter, behind the
`qwen` extra, with residual-stream hooks left reachable for Proposal C).

**Not implemented:** anything that reacts to a verdict. The Qwen3-8B adapter declares no
sources until taint propagation lands, so its runs measure the loop, not a defense — do
not report utility or security numbers from them.

**Exercised on:** `Qwen/Qwen3-0.6B` on CPU (torch 2.14+cpu, transformers 5.17), which is
a check of the adapter, not of the reference agent. Qwen3-8B has not been run. The slow
test loads `$TEKMOR_QWEN_MODEL` when it is set, so a machine that cannot hold 16 GB of
weights can still exercise the path:

```bash
uv pip install --index-url https://download.pytorch.org/whl/cpu torch
uv sync --extra qwen
TEKMOR_QWEN_MODEL=Qwen/Qwen3-0.6B uv run pytest -m slow
```

## Rules

- **`world.invoke` has exactly one call site**, in `ToolGateway.execute`, reached only
  after `mediate()` returned a verdict that permits it. Complete mediation is a property
  you should be able to confirm by reading that one method; adding a second path to the
  world destroys it. Every driver — the runner, the evaluation harness, an external
  harness adapter — goes through a `ToolGateway` rather than its own execution path.
- **The gateway decides nothing.** It is handed the decision `mediate()` produced.
  Keeping the two apart is what lets either be tested alone.
- **Unrecognised verdict executes nothing.** `ToolGateway.permitted` returns `None` by
  default, so a verdict added later fails closed until it is handled on purpose.
- **ESCALATE denies by default.** A run that wants approvals passes an `Approver`; a run
  that forgets does not silently get ALLOW.
- **The adapter never sees the verdict**, only the observation that follows it. An
  adapter that could read decisions would be able to probe the monitor for free.
- **`AgentState` carries the task and the step index only.** Do not add scenario
  identifiers, expected outcomes, or anything else a defense could recognise.
- Every decision is logged when a log is given, before the action executes.
- Tests use `ScriptedModel`. Anything needing a real backend is marked `slow`.
- **An adapter never invents provenance.** If it cannot say what influenced an action,
  it declares no sources and the lattice reads that as `ADVERSARY_CONTROLLED`.
- **A blocked action is only bounded by `max_steps`.** A real adapter re-proposes what it
  just had blocked, because the observation it gets back is the verdict string and
  nothing in the loop reacts to it. Observed on the 0.6B run; it is why `max_steps`
  exists, and it is what the "reacts to a verdict" gap above costs.
