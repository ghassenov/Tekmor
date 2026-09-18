# Tekmor

**Designing a Measurable Safety Layer for Tool-Using LLM Agents**

*Tekmor* (τέκμωρ): "sign, token, proof." The project's core principle is that untrusted
content is **evidence, not authority**, and that every safety decision must be provable
from its trace.

> **Status: foundation.** This repository contains the technical research report, the
> engineering standards, and the implementation so far: the decision contract every
> defense implements, a fail-closed mediation point, the trust lattice and taint
> propagation, the policy engine and the reference monitor with its capability
> downgrade, the encoding-aware canary scanner, the three baselines (allow-all,
> deny-sensitive, keyword), the append-only JSONL event log, the three-domain simulator
> with its scenario format, the runtime (scripted and Qwen3-8B adapters, run loop, tool
> gateway), and the evaluation harness that scores all of it. Calibrated risk scoring
> and its calibration metrics are **not implemented yet**; the numbers below come from
> this repository's own seven-scenario matrix, which is not a benchmark, and no external
> benchmark, robustness variant or adaptive attacker has been run.

## What this is

Tekmor is designed as an **action-centric reference monitor** for tool-using LLM agents,
not a prompt-injection classifier. Every candidate tool call passes through a decision
point that returns **ALLOW / BLOCK / ESCALATE / REWRITE** based on provenance, trust,
action risk, and policy.

The reasoning behind that choice, with citations, is in
[`docs/technical-doc.md`](docs/technical-doc.md): text-only detection defenses are
bypassed by adaptive attackers, while system-level designs that constrain *what actions
untrusted data can trigger* bound the blast radius regardless of whether the model was
fooled.

## High-level architecture (planned)

```
observation ─▶ [trust tagger] ─▶ [taint store: memory + tool-output fields]
                                          │
                     candidate action ────┤
                                          ▼
                    [policy engine: Trusted-Action + Permitted-Flow + least privilege]
                                          │  risk score + reason codes
                                          ▼
              ALLOW ── REWRITE (capability downgrade) ── ESCALATE ── BLOCK
                                          │
                                          ├─▶ tool gateway ─▶ world state
                                          ▼
                          append-only JSONL event + provenance graph edge
```

Six trust levels form a lattice used as integrity labels:

```
SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL >
UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED
```

The design direction is **Proposal A** (deterministic information-flow reference monitor)
as the core, with a task-alignment auditor (Proposal B) and an activation-delta drift
probe (Proposal C) as research extensions gated on the core being stable. See
`docs/technical-doc.md` for all three and their tradeoffs.

## Repository structure

```
src/tekmor/       implementation
  defense/        Defense interface, signals, risk scoring, decision + rewrite
  provenance/     trust lattice, taint propagation
  policy/         declarative policies and the policy engine
  observability/  event schema, append-only JSONL log, trace + provenance graph
  simulator/      synthetic world, typed tools, canary secrets, scenario format
  runtime/        ModelAdapter (mock + Qwen3-8B), runner, tool gateway
tests/            unit / integration / security / evaluation
evaluation/       scenarios (the matrix), harness, metrics, generated results
research/         literature, hypotheses, research experiments, notes
docs/             project documentation; technical-doc.md is authoritative,
                  decisions.md is the append-only decision log
.github/          PR template, issue templates, CI
```

Each of these directories has a `CLAUDE.md` with rules scoped to it; the root
[`CLAUDE.md`](CLAUDE.md) holds the project-wide engineering standards.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone git@github.com:ghassenov/Tekmor.git
cd Tekmor
uv sync --dev
cp .env.example .env    # then fill in; .env is gitignored
```

The package has no runtime dependencies. Two optional extras exist, each imported only
by the component that needs it:

```bash
uv sync --extra yaml    # PyYAML, for YAML scenario files (JSON needs nothing)
uv sync --extra qwen    # Transformers + torch, for the Qwen3-8B adapter
```

The scripted model backend is the default, so nothing so far requires a GPU or an API
key.

## Evaluation

```bash
uv run python -m evaluation.harness
```

Every scenario in `evaluation/scenarios/` runs under every defense; the run writes raw
decision events, per-run records and a manifest (commit, environment, input hashes) to
`evaluation/results/raw/<timestamp>/`, and the aggregate to `results/processed/`. Runs
are deterministic: the scripted adapter replays the scenario's steps and the simulated
human denies every escalation.

Measured on the seven-scenario matrix in this repository (three domains, benign and
attack halves), scripted adapter, reproduced by the command above:

| defense | BTU | ASR | CVR | FBR | UER |
|---|---|---|---|---|---|
| allow-all | 1.00 | 1.00 | 0.43 | 0.00 | n/a |
| deny-sensitive | 0.00 | 0.00 | 0.00 | 0.50 | n/a |
| keyword | 1.00 | 0.75 | 0.14 | 0.00 | n/a |
| tekmor | 1.00 | 0.25 | 0.14 | 0.00 | 0.00 |
| tekmor+canary | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 |

Read it as a sanity check on the mechanism, not as a result about prompt injection in
general: seven scenarios, scripted agents, and attacks written by the same person who
wrote the defense. The one attack `tekmor` misses is the mislabelled-secret scenario —
the argument-level residual a provenance rule cannot see — and the row below it is what
closes it. `deny-sensitive` is the reminder that ASR alone justifies nothing: it stops
every attack by stopping half the benign actions too.

## Development workflow

`main` is protected: pull requests are required, force-pushes and deletions are blocked,
and CI must pass. Never commit directly to `main`.

```bash
git checkout -b feat/<short-description>
# work, then:
uv run ruff format . && uv run ruff check . && uv run pytest
git commit          # Conventional Commits: feat(defense): ...
git push -u origin feat/<short-description>
gh pr create        # uses .github/pull_request_template.md
```

Branch prefixes: `feat/`, `fix/`, `refactor/`, `docs/`, `test/`, `research/`, `chore/`,
`perf/`, `security/`.

## Testing

```bash
uv run pytest                  # everything except tests needing a real model
uv run pytest tests/security   # adversarial tests
uv run pytest -m slow          # tests needing a real model backend or a GPU
```

The model-backed tests load `Qwen/Qwen3-8B` by default. `TEKMOR_QWEN_MODEL` overrides it
(`TEKMOR_QWEN_MODEL=Qwen/Qwen3-0.6B uv run pytest -m slow` exercises the adapter on CPU),
which checks the adapter, not the reference agent.

Test categories and their rules are in [`tests/CLAUDE.md`](tests/CLAUDE.md). Security
tests must include both attacks and benign hard negatives — a defense that blocks
everything is a failure, so false-block rate is a headline metric.

## Evaluation

Not built yet. The planned metrics (defined in `docs/technical-doc.md` Part VI) are
benign task utility (BTU), attack success rate (ASR), canary violation rate (CVR),
false-block rate (FBR), and unnecessary escalation rate (UER), alongside calibration
(ECE) and time-to-detection. Planned evidence is Tekmor's own scenarios with paraphrase,
encoding, and adaptive-attacker variants, plus [AgentDojo](https://agentdojo.spylab.ai)
as external validation.

Evaluation rules — reproducibility, versioned scenarios, baselines, raw/processed
separation, and no hand-edited results — are in
[`evaluation/CLAUDE.md`](evaluation/CLAUDE.md).

## Research workflow

Literature notes, hypotheses, and exploratory experiments live in `research/`, under the
rules in [`research/CLAUDE.md`](research/CLAUDE.md): explicit falsifiable hypotheses, real
citations, recorded negative results, and a clear separation between observation and
interpretation. Results are never fabricated, and claims are labelled **implemented /
tested / observed / hypothesized / planned / inferred**.

## Contributing

Open an issue using one of the templates in `.github/ISSUE_TEMPLATE/` (bug, feature,
research, security), then work on a branch and open a PR. The PR template asks for
security, research, and observability implications along with known limitations — filling
those in honestly is part of the contribution.

## License

[MIT](LICENSE).
