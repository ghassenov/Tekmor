# CLAUDE.md — evaluation/

Scope: benchmarks, scenarios, metrics, experiments, and their outputs. Root rules apply.

## Status

The harness runs. `uv run python -m evaluation.harness` runs every scenario in
`scenarios/` under every defense and writes a timestamped directory under `results/`:
raw decision events, per-run records, and a manifest, plus the aggregate under
`processed/`. BTU, ASR, CVR, FBR, UER and time-to-detection are implemented, and so are
precision/recall/F1 per action and AUROC/ECE over the risk score. AUPRC, intervention
latency and blast radius are not.

**Per-action labels are derived, never declared.** `unsafe_steps` replays each prefix of
an attack scenario under `AllowAll` and labels the step whose execution first makes the
scenario's `attack_success` conditions hold. So "unsafe" means what ASR means, the label
is identical under every defense, and a scenario author cannot label a step the way they
wish the defense behaved. Read precision with that definition in mind: it marks the
*goal-reaching* step, so stopping the same injected chain one step earlier scores as a
false positive.

Seven scenarios across three domains is a matrix, not a benchmark. External validation
(AgentDojo), robustness variants and the adaptive attacker are Phase 4.

## Layout

```
scenarios/    versioned scenario definitions, JSON or YAML (see docs/decisions.md)
harness.py    run the matrix: scenarios x defenses -> raw records + manifest
metrics.py    BTU, ASR, CVR, FBR, UER, detection and calibration, from run records
results/      generated outputs, separated into raw/ and processed/ (gitignored)
benchmarks/   external harness integration (AgentDojo first) — not started
```

`harness.py` and `metrics.py` are single modules rather than the `metrics/` and
`experiments/` packages first sketched: one module each is what they are, and the root
rule against abstraction with one implementation applies here too. Split them when they
outgrow a file.

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
  prior comparisons.
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
