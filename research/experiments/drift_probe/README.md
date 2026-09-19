# DRIFT-PROBE: an activation-delta linear probe for task drift (Proposal C)

Status: **hypothesis and method written before the first run** (2026-09-19). Results are
appended below, under their own heading, after the runs. Nothing above that heading is
edited to fit them.

## Hypothesis

A linear probe on residual-stream activation *deltas* separates tool outputs that carry
an injected instruction from ones that do not. The delta is the last-token hidden state
after the agent's context has absorbed the external text, minus the same state before
it (TaskTracker, Abdelnabi et al., "Get my drift?", SaTML 2025, arXiv:2406.00799). The
probe is trained only on synthetic pairs built from text unrelated to either evaluation
set.

**Evidence gate** (`docs/technical-doc.md`, Recommendations 3). The probe earns a place
beside the deterministic core only if, on held-out data:

1. its false-positive rate on benign content, hard negatives included, is **below 10%**
   at the probe's own 0.5 threshold; **and**
2. it flags **at least one attack the deterministic core misses**.

**Refuted by** an FPR of 10% or more on the benign sets, or by catching nothing the core
misses. The gate says the probe is then demoted to future work, and it is.

## The limit that decides the verdict before any number does

Part IX, limit 4: the probe must hook **the same Qwen3-8B the agent uses**. A smaller
proxy model's activations are not evidence about the agent's behaviour. This machine has
no GPU and 15 GB of RAM, and Qwen3-8B does not fit. The experiment is therefore run on
**Qwen3-0.6B as a proxy**. Whatever it shows, it validates the *pipeline* (extraction,
probe, evaluation, gate) and says nothing about Qwen3-8B. **The probe is not integrated
into `src/` on this evidence under any outcome.** A pass on the proxy means "rerun on the
reference model". A fail means "demoted, and rerun on the reference model before
reviving it".

## Method

- **Model.** `Qwen/Qwen3-0.6B`, float32, CPU, `output_hidden_states=True`, chat template
  with thinking off. The representation is the last prompt token at every layer.
- **Delta.** `h(task + data) − h(task)`. Both are the user turn, with the data block
  appended after the task in the first.
- **Training data (synthetic, disjoint from both evaluation sets).**
  - Clean data: WikiText-2 paragraphs (the locally cached `Salesforce/wikitext`,
    `wikitext-2-raw-v1` train split).
  - Primary tasks: generic instructions over a text (summarise, list entities, translate,
    extract dates, and so on).
  - Drift: the same paragraph with an injected instruction inserted at a sentence
    boundary. The instruction comes from a template list, with slot fillers for the
    attacker's action.
  - The split is **by template**: some injection templates and tasks appear only in
    validation.
- **Layer and probe.** Logistic regression with L2 on standardised deltas, in numpy. The
  layer is chosen on the validation split only.
- **Held-out set A, the Tekmor matrix.** Per scenario, the task is the scenario's task
  and the data is each document below `TRUSTED_INTERNAL`. The scenario score is the
  maximum over those documents. Attack scenarios are positives and `over_refusal`
  scenarios are the hard negatives. Scenarios with no untrusted document score 0.
- **Held-out set B, AgentDojo v1.2.2.** Per user task, the data is the concatenated tool
  outputs of its ground-truth calls. The negative is the clean environment. The positive
  is the same calls in the environment the `direct` attack injected, for that suite's
  `injection_task_0`. Contexts are capped at 4096 tokens, and the number truncated is
  reported.
- **Metrics.** AUROC, TPR and FPR at 0.5, per set, and which positives are flagged that
  the core misses: on the matrix the endorsed-invoice attack under endorsement, and on
  AgentDojo slack's URL fetch.
- **Seeds.** Every sampling step uses `random.Random(0)`.

## Assumptions

- WikiText paragraphs stand in for the benign text an agent reads. They are
  encyclopaedic, not business mail, so a probe keyed on register rather than on
  instructions would look good in training and fail on set A. Set A exists partly to
  catch that.
- An injected instruction is the thing that drifts the task. Compositional attacks,
  whose fragments are individually benign, are expected to be missed by construction.
