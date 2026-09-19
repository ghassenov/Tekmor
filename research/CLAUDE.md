# CLAUDE.md — research/

Scope: literature, hypotheses, exploratory experiments, and notes. Root rules apply.

## Status

`experiments/drift_probe/` is the first experiment: Proposal C's activation-delta probe,
pre-registered, run on a Qwen3-0.6B proxy, and refuted by its own gate (a negative result,
kept). `docs/technical-doc.md` still holds the literature review; move or extend it here
as notes accumulate rather than duplicating it.

## Intended layout

```
literature/   per-paper notes: claim, method, reported numbers, limitations, citation
hypotheses/   falsifiable hypotheses with their evaluation plan
experiments/  exploratory experiments and analysis
notes/        working notes and decision history
```

Research code is exploratory but must stay understandable and reproducible. It must not
become a production dependency: if an experiment earns a place in the core, refactor it
into `src/` with tests instead of importing from here.

## Rules

- **State the hypothesis explicitly and make it falsifiable** before running anything —
  the form is "X holds under conditions Y, measured by metric Z, and would be refuted by
  W". Write it down first so the result cannot be retrofitted to the outcome.
- A research note should let a reader reconstruct: hypothesis, methodology, variables,
  baseline, experiment configuration, metrics, results, limitations, and interpretation.
- **Separate observation from interpretation.** Keep what was measured and what it might
  mean in distinct sections, and label every claim: implemented / tested / observed /
  hypothesized / planned / inferred.
- **Record negative results.** An experiment that failed or showed no effect is a finding
  and belongs here. Silently dropping them biases everything that follows.
- **Cite properly and never fabricate a reference.** Every literature note keeps its
  source (arXiv ID, venue, repo) and attributes reported numbers to the paper that
  reported them, noting the benchmark and attack set they were measured on.
- **Document assumptions**, especially where an external result is assumed to transfer to
  Tekmor's setting.
- Notes are append-oriented: keep the history of how an idea evolved, including
  abandoned directions and why they were abandoned.
