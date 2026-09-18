# CLAUDE.md — src/tekmor/simulator/

Scope: the synthetic world the agent acts in. Root and `src/` rules apply.

## Status

**Implemented:** `world.py` (mutable state, typed tools, canary tagging on outbound
calls), `domains.py` (the enterprise tool set), `scenario.py` (JSON scenario format and
its validation).

**Not implemented:** the financial and SOC domains, the scenario matrix, and robustness
variants (paraphrase / base64 / hex / spaced / reversed).

## Rules

- **The simulator never imports from `defense/`.** It produces labelled observations and
  executes approved calls; it must not be able to influence or anticipate a decision.
- **Scenario metadata (`id`, `version`, `benign`) must never reach the defense.** Only
  the task, the action, its provenance, and the policy do. A defense that can recognise
  a test case is not evidence of security.
- **Outcomes are world state.** Utility and attack success are read off `World` (sent
  mail, drafts, `leaked`), never off what the agent claimed to do.
- `World.canaries_in` is ground truth for scoring, not a defense. It matches verbatim
  only, so it under-reports; the encoding-aware scanner is a defense component.
- Tools are typed and explicit. `outbound` says where the data goes and belongs to the
  tool; *sensitivity* is per-domain judgement and belongs to `Policy`.
- Scenarios are immutable once results reference them: change means a new `version`.
