# Tekmor

**A measurable safety layer for tool-using LLM agents.**

*τέκμωρ — "sign, token, proof".*

Tekmor sits between an LLM agent and the tools it can call. Every candidate tool call is
checked against where its influences came from, and allowed, blocked, deferred to a human,
or rewritten into something less dangerous. Its guiding principle is one sentence:

> **Untrusted content is evidence, not authority.**

An agent may *read* a hostile email, a poisoned invoice or an attacker-controlled web
page. What that content is not allowed to do is *authorise* a consequential action.

---

## The problem

Tool-using agents read from places their user does not control — inbound mail, web pages,
documents, API results, their own memory — and they can also spend the user's authority:
send money, share files, delete records. Those two capabilities meet inside one context
window, so text that was merely *read* can end up *instructing*. This is indirect prompt
injection, and it is a confused-deputy problem.

The common answer is a classifier that tries to spot malicious text. The literature is
consistent that this does not hold: adaptive attackers reach over 50% success against
eight published defenses in one study, and over 90% against all twelve in another.
Rephrase, encode, translate — the classifier misses.

Tekmor takes the other route. It never asks *"is this text malicious?"* It asks *"given
everything that influenced this call, is this call permitted?"* — a question rewording
does not change.

## What that buys

![Scenario matrix: attack success, benign utility and false blocks](assets/matrix-baselines.png)

On the internal scenario matrix — 26 scenarios, seven attack families, difficulty levels
1–5 — Tekmor completes **every** benign task with a **zero** false-block rate, while
bringing attack success from 1.00 to 0.06. The only baseline with comparable security,
`deny-sensitive`, reaches it by completing 12% of the work and falsely blocking a quarter
of all benign actions.

That second half matters as much as the first. A security layer that blocks legitimate
work gets switched off, so **false-block rate is a headline metric** and roughly a third
of the test matrix is benign work that merely *looks* alarming.

## Which part actually works

![Ablations: attack success rate with one input removed](assets/ablations.png)

Ablations remove one input at a time. **Provenance carries the result**: without it, 94%
of attacks land. This is measured, not asserted — and it is the kind of claim a project
should be able to make about itself before asking anyone to trust it.

## Under adaptive attack

![Adaptive attacker: ASR per round](assets/adaptive-attacker.png)

An attacker that hill-climbs over encodings, rewordings and read order — seeing the
verdicts and public reason codes, as a real attacker would — breaks the keyword filter
within five rounds and does not move the monitor across fifty.

## The honest picture

![AgentDojo: benign utility against attack success](assets/agentdojo-frontier.png)

On [AgentDojo](https://arxiv.org/abs/2406.13352) — someone else's tasks, injections and
checks — the result is harder. Call-level taint over-taints: benign utility falls to 0.45,
matching `deny-sensitive` on three suites of four. Every mechanism tried since has been a
**trade** rather than a dominance, and each is recorded as such.

Two further results are worth knowing before reading anything else here:

- **An LLM "alignment judge" added essentially nothing.** Running the same mechanism with
  no judge at all — refuse every ambiguous action, ask nobody — reproduced both GPU judges
  almost exactly. Their entire measurable contribution was 2–4 benign runs out of 97.
- **The activation-drift probe failed its pre-registered gate twice**, at 0.6B and again at
  8B. It learned that *external text arrived*, not that *an instruction arrived*.

**And the standing caveat:** every AgentDojo number in this repository came from a driver
that replays ground truth and obeys every injection. ASR is therefore an *always-obeys
upper bound*, not a measurement, and none of it is comparable with CaMeL, FIDES or Task
Shield. The attempt to remove that confound with a real model has not yet produced a valid
run. See [limitations.md](docs/limitations.md) — it is the most important document here.

## How it works, briefly

Every tool call passes through one function:

```python
Defense.decide(state, action, provenance, policy) -> Decision
```

returning **ALLOW**, **BLOCK**, **ESCALATE** (defer to a human) or **REWRITE** — a
least-privilege downgrade along a capability lattice, where `send_email` becomes
`draft_email` and `execute_payment` becomes `prepare_payment`. The task keeps moving; the
irreversible effect is removed.

![Tekmor decision flow](assets/decision-flow.svg)

Trust is a six-level lattice from `SYSTEM_POLICY` down to `ADVERSARY_CONTROLLED`. An
action's integrity is the *lowest* trust among everything that influenced it, and unknown
provenance is never treated as trusted. Reason codes are the literal predicates that
fired, so an explanation cannot disagree with the decision it explains.

![Trust lattice, and integrity as the meet](assets/trust-lattice.svg)

## Documentation

| Document | What is in it |
|---|---|
| [architecture.md](docs/architecture.md) | The reference monitor, the four verdicts, how a decision is computed |
| [threat-model.md](docs/threat-model.md) | The adversary, the seven attack families, what is out of scope |
| [provenance.md](docs/provenance.md) | The trust lattice, taint propagation, endorsement, finer granularity |
| [evaluation.md](docs/evaluation.md) | Metrics, baselines, the two evaluation surfaces, pre-registration |
| [results.md](docs/results.md) | Every measured result, with figures |
| [limitations.md](docs/limitations.md) | **What the numbers do not support.** Read this one. |
| [technical-doc.md](docs/technical-doc.md) | The authoritative research report: threat model, literature, roadmap |
| [decisions.md](docs/decisions.md) | Append-only log of every decision and result, with its caveats |

Research experiments live in `research/experiments/`, each with a pre-registration
committed *before* its first run.

## Quickstart

Python 3.12+, managed with [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-extras
uv run pytest                              # unit, integration, security, evaluation
uv run ruff check . && uv run ruff format .

uv run python -m evaluation.harness        # the scenario matrix
uv run python -m evaluation.ablations      # remove one input at a time
uv run python -m evaluation.adaptive       # the hill-climbing attacker
uv run python -m evaluation.dojo           # AgentDojo (needs the agentdojo extra)
```

Runtime dependencies are **empty by design**. Everything optional is an extra, imported
inside the component that needs it: `yaml` for YAML scenarios, `qwen` for the local model
adapter, `agentdojo` for external validation, `docs` for regenerating figures.

To regenerate the figures in `assets/`:

```bash
uv sync --extra docs
uv run python assets/figures.py
```

## Repository layout

```
src/tekmor/       the implementation
  defense/        decision contract, signals, risk scoring, monitor, rewrite, canary, auditor
  provenance/     trust lattice, taint propagation, endorsement, canary matcher
  policy/         declarative per-domain policies and their predicates
  observability/  event schema, append-only JSONL log, timeline and provenance graph
  simulator/      three synthetic worlds, typed tools, canary secrets, scenario format
  runtime/        model adapters, the run loop, the tool gateway
tests/            unit / integration / security / evaluation
evaluation/       scenarios, harness, metrics, ablations, variants, adaptive, AgentDojo
research/         literature, hypotheses, pre-registered experiments
notebooks/        Colab notebooks for the runs that need a GPU
assets/           documentation figures and the script that regenerates them
docs/             project documentation
```

## Project status

The five roadmap phases are complete and the work now is measurement. The decision core,
policy engine, provenance and taint propagation, canary scanner, simulator, observability
and the evaluation harness are implemented and tested; the scenario matrix, robustness
variants, ablations, the adaptive attacker and AgentDojo all run.

Several mechanisms are **built, measured and deliberately switched off** — argument-level
provenance, field-level labels, the alignment auditor. The reasons are recorded in
[decisions.md](docs/decisions.md), and in at least one case the reason is methodological
rather than numerical: a fix diagnosed on a held-out benchmark cannot be adopted on that
benchmark's own numbers.

This is research code. Results on this repository's own scenarios are only as convincing
as the scenarios are hard and independent of the defense's design, which is why AgentDojo
is here and why [limitations.md](docs/limitations.md) is written the way it is.

## License

MIT. See [LICENSE](LICENSE).
