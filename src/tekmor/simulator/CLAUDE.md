# CLAUDE.md — src/tekmor/simulator/

Scope: the synthetic world the agent acts in. Root and `src/` rules apply.

## Status

**Implemented:** `world.py` (mutable state, typed tools, labelled content and
observations, canary tagging on outbound calls, the payment lifecycle invariant),
`domains.py` (the enterprise, financial and SOC tool sets), `scenario.py` (the scenario
format, its validation, and the JSON and YAML front ends).

The scenario matrix is complete: twenty-four scenarios in `evaluation/scenarios/` cover
the seven attack families at levels 1-5, and a scenario declares its `family` and `level`
(see `evaluation/CLAUDE.md`). Memory is `remember`/`recall` over the ordinary document
store, and the store **launders trust on purpose** — `remember` labels what it is handed
as ordinary internal content, so what refuses a poisoned recall is the run's taint rather
than a careful store. `lookup_vendor` and `enrich_indicator` are the same read under
names that say where the content came from, which is what makes tool-output tampering
legible in a trace.

**Not implemented:** robustness variants (paraphrase / base64 / hex / spaced / reversed)
as *generated* transformations — the encodings appear in hand-written scenarios today —
and memory that carries a label across runs, so the cross-session poisoning case is a
declared document.

## Rules

- **The simulator never imports from `defense/`.** It produces labelled observations and
  executes approved calls; it must not be able to influence or anticipate a decision.
- **Content carries the label, steps never do.** A document states the integrity of
  whoever wrote it; what influenced an action is computed from the reads the run
  performed (`tekmor.provenance.taint`). A scenario that could label a step would be
  choosing the defense's input, which is the same defect as letting the defense read
  `benign`. `parse_scenario` rejects both a step that declares sources and a document
  that states no trust — guessing a label either invents trust or turns every scenario
  into an attack.
- **Scenario metadata (`id`, `version`, `benign`, `family`, `level`) must never reach
  the defense.** Only the task, the action, its provenance, and the policy do. A defense
  that can recognise a test case is not evidence of security.
- **Outcomes are world state.** Utility and attack success are read off `World` (sent
  mail, drafts, `leaked`), never off what the agent claimed to do.
- `World.canaries_in` is ground truth for scoring, not a defense. It matches verbatim
  only, so it under-reports; the encoding-aware scanner is a defense component.
- Tools are typed and explicit. `outbound` says where the data goes and belongs to the
  tool; *sensitivity* is per-domain judgement and belongs to `Policy`.
- Scenarios are immutable once results reference them: change means a new `version`.
- **`parse_scenario` is the only definition of the scenario format.** JSON and YAML are
  front ends onto it and must produce equal `Scenario` objects; validation never moves
  into a loader. YAML needs the `yaml` extra and is imported inside `load_scenario`.
- **Lifecycle constraints belong to the world, not to a defense.** `execute_payment`
  refuses an unconfirmed payment because that is how payments work, so attack success
  stays a fact about world state rather than something a defense has to assert.
