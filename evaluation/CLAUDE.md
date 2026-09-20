# CLAUDE.md — evaluation/

Scope: benchmarks, scenarios, metrics, experiments, and their outputs. Root rules apply.

## Status

The harness runs. `uv run python -m evaluation.harness` runs every scenario in
`scenarios/` under every defense and writes a timestamped directory under `results/`:
raw decision events, per-run records, and a manifest, plus the aggregate under
`processed/`. BTU, ASR, CVR, FBR, UER and time-to-detection are implemented, and so are
precision/recall/F1 per action and AUROC/AUPRC/ECE over the risk score, plus the
pass/fail grid by attack family and level (`metrics.grid`). Intervention latency and
blast radius are not.

`calibration.py` is CALIB-RISK: it Platt-scales the risk score **leave-one-scenario-out**
and reports ECE, Brier and AUROC raw and calibrated over the same held-out actions. The
fold is the scenario, never the action — actions inside one run share a world, a policy
and an injected chain, so an action-level split trains on an action's near-twin. On the
seven-scenario matrix the calibration was *worse* than the ordinal scale; on the full
twenty-four it improves ECE (0.07 -> 0.04) with no inverted fold, which is the reversal
the earlier entry said a larger matrix would decide. Only the raw-versus-calibrated
comparison *within* one matrix is meaningful — the two matrices are different samples —
and the fit still costs a little ranking, so the scale in use stays ordinal. Both results
are in `docs/decisions.md`. The harness also writes a `timeline.html` beside each
`decisions.jsonl` (`tekmor.observability.viewer`).

**Per-action labels are derived, never declared.** `unsafe_steps` replays each prefix of
an attack scenario under `AllowAll` and labels the step whose execution first makes the
scenario's `attack_success` conditions hold. So "unsafe" means what ASR means, the label
is identical under every defense, and a scenario author cannot label a step the way they
wish the defense behaved. Read precision with that definition in mind: it marks the
*goal-reaching* step, so stopping the same injected chain one step earlier scores as a
false positive.

**The matrix is the grid.** Twenty-four scenarios across three domains cover all seven
attack families of `docs/technical-doc.md` Part I at levels 1-5, seven of them benign
(`over_refusal`, the family whose failure mode is refusing legitimate work). A scenario
states its `family` and `level`; both are scorer metadata and never reach a defense, and
`parse_scenario` rejects a family outside the taxonomy or one that disagrees with
`benign`. Level 4 is represented by static rewordings in the matrix itself. The adaptive attacker
(`adaptive.py`) mutates against observed decisions, but only over the argument channel
of a scripted agent.

Twenty-four scenarios across three domains is still a matrix, not a benchmark: written by
the same people who wrote the defense, and every attack a scripted path. External
validation is `dojo.py`, on AgentDojo's own tasks and checks.

**Robustness variants** (`variants.py`, `uv run python -m evaluation.variants`) transform
what an attacker controls (untrusted document text, the scripted steps' argument values,
the order of consecutive reads) and rewrite the outcome conditions to match. Each variant
is replayed under `AllowAll` first and *rejected and listed* if its attack no longer lands
or its benign task no longer completes. Variants are reported paired with their originals
(ASR/BTU original > variant, and the runs that flipped) and never mixed into the headline
metrics. Results land under `results/{raw,processed}/<stamp>-variants/`. With the scripted
adapter, document rewrites reach no decision; the variants probe the argument channel.

**Ablations** (`ablations.py`, `uv run python -m evaluation.ablations`) wrap the unchanged
monitor and remove one *input* each: provenance, propagation (only the latest observation
counts), or the capability lattice. Rules-only and full are `tekmor` and `tekmor+canary`.
Results land under `results/{raw,processed}/<stamp>-ablations/`. The numbers, and why the
no-rewrite row cannot move on this matrix, are in `docs/decisions.md`.

**The adaptive attacker** (`adaptive.py`, `uv run python -m evaluation.adaptive`) climbs
over a genome of encoding, rewording and read order. Each candidate is rebuilt from the
original, and it is replayed undefended before it is scored. Its fitness reads only what
an attacker observes: its goal, the verdicts, and the public reason codes, never the risk
score. Results land under `results/{raw,processed}/<stamp>-adaptive/`, with the seed and
the budget in the manifest.

**AgentDojo** (`dojo.py`, needs `uv sync --extra agentdojo`) runs the pinned suites with
Tekmor as a pipeline element. It scores with AgentDojo's own checks, against the calls
that *executed*, and counts pairs whose attack does not land undefended as invalid. The
per-suite `sensitive`/`trusted` configuration is deployment input, frozen: do not tune it
on AgentDojo results, because AgentDojo is the held-out set. Results land under
`results/{raw,processed}/<stamp>-agentdojo/`.

`--agent` picks the driver, and the manifest records which one ran. `ground-truth` is the
default and produced every recorded number: it replays AgentDojo's ground truth and obeys
every injection, so its ASR is the always-obeys bound and its BTU asks only whether the
policy would have permitted the oracle trace. `model` drives an OpenAI-compatible
endpoint through AgentDojo's own pipeline, with `TekmorExecutor` in `ToolsExecutor`'s
slot, and needs a served model and a GPU. **Numbers from the two drivers measure
different things and never belong in one table.**

## Layout

```
scenarios/    versioned scenario definitions, JSON or YAML (see docs/decisions.md)
harness.py    run the matrix: scenarios x defenses -> raw records + manifest
metrics.py    BTU, ASR, CVR, FBR, UER, detection and ECE, from run records
calibration.py  CALIB-RISK: the Platt fit, the held-out protocol, and its own controls
variants.py   robustness variants: encode / reword / reorder, validated and paired
ablations.py  the monitor with one input removed: provenance, propagation, rewrite
adaptive.py   the adaptive attacker: a seeded hill climb, ASR reported per round
results/      generated outputs, separated into raw/ and processed/ (gitignored)
dojo.py       AgentDojo: Tekmor as a pipeline element, ground truth as a fooled agent
alignment.py  Proposal B: the monitor with and without the task-alignment auditor
```

`harness.py`, `metrics.py` and `calibration.py` are single modules rather than the
`metrics/` and `experiments/` packages first sketched: one module each is what they are,
and the root rule against abstraction with one implementation applies here too. Split them
when they outgrow a file. `calibration.py` is separate from `metrics.py` because it is the
one thing in here that *fits* something — it has a training protocol to get wrong, and
keeping it beside the metrics it is scored by would blur which numbers were learned.

Evaluation depends on `src/`; `src/` never depends on evaluation. Keeping the harness
independent is what stops the defense from being tuned against its own scorer.

## Rules

- **Reproducibility is the point.** Every run records model and version, configuration,
  scenario version, seeds, prompts, policies, defense configuration, metrics, and
  environment. A result that cannot say how it was produced is not a result.
- **Deterministic where possible.** Fixed seeds, pinned scenario versions, mock adapter
  for infrastructure tests. Record any unavoidable nondeterminism explicitly.
- **Versioned scenarios.** Scenarios are immutable once results reference them; changing
  one means a new version, so old results stay interpretable.
- **Explicit metrics.** Use the definitions in `docs/technical-doc.md` Part VI (BTU, ASR,
  CVR, FBR, UER, plus precision/recall/F1, AUROC/AUPRC, ECE, time-to-detection, latency,
  blast radius). Do not redefine a metric silently; changing a definition invalidates
  prior comparisons. Report an imbalance-sensitive metric beside its chance line: AUPRC
  is meaningless without the base rate next to it.
- **Anything fitted is fitted out-of-sample, and the fold is the scenario.** A number
  produced by a model trained on the actions it scores is a report of the fit, not of the
  thing. Report the raw and fitted versions over the *same* held-out actions, keep the
  controls that would expose a broken fit (`inverted_folds`), and report a negative
  result as a result.
- **Always report a baseline.** Undefended, allow-all, deny-sensitive, and keyword
  baselines give every number a reference point. A number without a baseline says nothing.
- **Separate raw from processed results.** Raw run outputs are write-once; analysis
  produces new files and never edits the raw ones.
- **Never hand-edit results, and never fabricate them.** No fake benchmark scores,
  ablations, or performance measurements. If a run failed, record the failure.
- **Write hard scenarios before tuning the defense**, and freeze a held-out set. Report
  held-out results separately from development results.
- The scenario/variant generator must never pass scenario metadata to the defense.
- Report failures and negative ablation results. Ablations exist to show where the system
  breaks; omitting the unflattering ones makes the rest untrustworthy.
