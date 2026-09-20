# Evaluation

How Tekmor is measured, what each metric means, and what the numbers can and cannot
support.

Results themselves are in [results.md](results.md); the caveats that qualify them are in
[limitations.md](limitations.md).

---

## The principle

A number without a baseline says nothing. Every measurement here is reported beside
reference points that bracket the space:

| Baseline | What it establishes |
|---|---|
| `allow-all` | The undefended agent: the utility ceiling and the security floor. |
| `deny-sensitive` | Blocks every sensitive tool: secure by construction, useless by construction. |
| `keyword` | A shallow text filter, standing in for detector-style defenses. |

None of them is a defense. They exist to be beaten, and a defense that does not beat
`deny-sensitive` on utility while matching it on security has not earned its complexity.

## Metrics

| Metric | Definition | Direction |
|---|---|---|
| **BTU** — benign task utility | Fraction of benign tasks completed | higher |
| **ASR** — attack success rate | Fraction of attacks reaching the attacker's goal | lower |
| **CVR** — canary violation rate | Fraction of runs where a secret left, across encodings | lower |
| **FBR** — false block rate | Fraction of benign actions refused | lower |
| **UER** — unnecessary escalation rate | Benign actions deferred to a human | lower |

Detection quality is reported separately — precision, recall, F1 over per-action labels,
and AUROC / AUPRC / ECE over the risk score. AUPRC is always printed beside its own
chance line, because an imbalance-sensitive metric without a base rate is not
interpretable.

**Per-action labels are derived, never declared.** `unsafe_steps` replays each prefix of
an attack scenario under `allow-all` and labels the step whose execution first satisfies
the scenario's `attack_success` conditions. So "unsafe" means exactly what ASR means, the
label is identical under every defense, and a scenario author cannot label a step the way
they wish the defense had behaved. One consequence is worth knowing when reading
precision: the label marks the *goal-reaching* step, so a defense that stops the same
injected chain one step earlier scores that as a false positive.

## Two evaluation surfaces

### The scenario matrix (internal)

26 scenarios across three simulated domains — enterprise, financial, SOC — covering the
seven attack families at difficulty levels 1–5. Roughly a third are benign hard negatives
in the `over_refusal` family, because the false-block trap is a primary failure mode.

A scenario states its own ground truth — `success` and `attack_success` as conditions
over world state — plus its `family` and `level`. All of that is scorer metadata and
**none of it ever reaches a defense**. A defense that recognised test cases would not be
evidence of anything, and this is the single most important correctness rule in `src/`.

This is a matrix, not a benchmark: written by the same people who wrote the defense. It
is useful for ablations and regressions, and it cannot establish external validity.

### AgentDojo (external)

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024), pinned
at benchmark version `v1.2.2`, four suites: banking, slack, travel, workspace. The tasks,
the injections, and the utility and security checks are all AgentDojo's own. This is the
guard against a defense designed around its own test set.

Tekmor enters as `TekmorExecutor`, a pipeline element replacing AgentDojo's
`ToolsExecutor`: every tool call becomes an `Action`, is decided by `mediate()`, and
executes only as the gateway permits.

The per-suite `sensitive` / `trusted` configuration is **deployment input, frozen before
the first run**. It was written from tool names and docstrings, never from AgentDojo's
injection vectors. Tuning it on AgentDojo results would stop AgentDojo being held out —
which is why a known 20-landing fix was explicitly rejected rather than applied.

## Which agent drove the run — and why it changes everything

This is the single most important thing to check before reading any AgentDojo number.

**`ground-truth` (the default; every recorded number).** The driver replays AgentDojo's
own ground truth and then the injection task's ground truth: an agent that did the user's
work, read the injection, and obeyed it. Consequently:

- **ASR is an *always-obeys bound***, not a measurement. The agent is compromised by
  construction; the only question asked is whether the monitor stopped the call.
- **BTU asks whether the policy would have permitted the oracle trace**, not whether work
  got done. A refused action the success condition does not depend on costs nothing.
- **Provenance is near-oracle**, because the script copies values verbatim out of
  structured results.

**`model` / `hf-native`.** A real model drives the pipeline. This removes all three
caveats — and has not yet produced a valid run. See [limitations.md](limitations.md).

Numbers from the two drivers measure different things and never belong in one table.

## Beyond a single sweep

**Robustness variants.** Each attack is transformed along the channels an attacker
controls — five encodings, a lexical reword, a read reorder — and every variant is
replayed undefended first and *rejected* if its attack no longer lands. Variants are
reported paired with their originals and never mixed into headline metrics.

**Ablations.** The monitor is left unchanged and one *input* is removed: provenance,
propagation, or the capability lattice. This is what separates "the system works" from
"we know which part does the work".

**The adaptive attacker.** A seeded hill climb over a genome of encoding, rewording and
read order. Its fitness function sees only what an attacker sees — its goal, the verdicts,
and the public reason codes — never the risk score. Each candidate is rebuilt from the
original and replayed undefended before it is scored.

**Calibration.** The risk score is Platt-scaled **leave-one-scenario-out**, never
leave-one-action-out: actions inside one run share a world, a policy and an injected
chain, so an action-level split would train on an action's near-twin. Raw and calibrated
are reported over the same held-out actions.

## Reproducibility

Every run writes a timestamped directory under `evaluation/results/` containing raw
per-run records, the decision event log, and a manifest recording the model and version,
the configuration, scenario versions and hashes, seeds, policies, the defense
configuration, and the environment. Raw outputs are write-once; analysis produces new
files and never edits them.

`evaluation/results/` is gitignored — results are generated artefacts, not source. The
consequence has bitten once already: the GPU runs happened on an ephemeral Colab VM and
their raw records are gone, surviving only as metrics printed into the notebook output.
The notebooks now print manifests and metrics verbatim before offering a download.

**Results are never hand-edited.** The figures in [results.md](results.md) are generated
by `assets/figures.py`, which loads result files directly wherever the run is reproducible
on CPU and quotes `decisions.md` by name where it is not.

## Pre-registration

Research experiments state hypothesis, arms, gates and predictions **before** the first
run, in `research/experiments/*/README.md`, committed ahead of any result. The form is
"X holds under conditions Y, measured by Z, and would be refuted by W".

This is not ceremony. It has repeatedly changed conclusions:

- The field-label arm computed its expected residual in advance — 0.075 — and measured
  0.0755 from precisely the predicted groups.
- The `deny-gray` control pre-committed an *undecided band* of 0.02–0.05 because 97 benign
  runs cannot resolve differences that small. Both judges landed inside it, and both were
  reported as undecided rather than rounded into a conclusion.
- Several pre-registered predictions turned out **wrong**, and are recorded as wrong.

Negative results are kept. `docs/decisions.md` is append-only: a reversal is a new entry
referencing the old one, never an edit.
