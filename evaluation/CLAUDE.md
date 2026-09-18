# CLAUDE.md — evaluation/

Scope: benchmarks, scenarios, metrics, experiments, and their outputs. Root rules apply.

## Status

Planned. Nothing here has been run; no results exist yet.

## Intended layout

```
benchmarks/   external harness integration (AgentDojo first)
scenarios/    versioned scenario definitions (YAML)
metrics/      metric implementations: BTU, ASR, CVR, FBR, UER, calibration
experiments/  experiment configurations and runners
results/      generated outputs, separated into raw/ and processed/
```

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
