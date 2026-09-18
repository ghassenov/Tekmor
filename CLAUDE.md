# CLAUDE.md — Tekmor

Project-level instructions for coding agents. Scoped rules live in nested `CLAUDE.md`
files (`docs/`, `src/`, `src/defense/`, `src/provenance/`, `src/policy/`,
`src/observability/`, `tests/`, `evaluation/`, `research/`). Read the nested file for the
directory you are working in; it does not repeat this one.

## Project Context

Tekmor (τέκμωρ: "sign, token, proof") is a research project building a **measurable
safety layer for tool-using LLM agents**. Its core principle: untrusted content is
**evidence, not authority**, and every safety decision must be provable from its trace.

Tekmor is an **action-centric reference monitor**, not a prompt-injection classifier.
Every candidate tool call passes through `Defense.decide(state, action, provenance,
policy) -> Decision`, which returns **ALLOW / BLOCK / ESCALATE / REWRITE** based on
provenance, trust, action risk, and policy. The rationale (text-only detection defenses
are broken by adaptive attackers; flow/policy defenses bound blast radius regardless) is
documented with citations in `docs/technical-doc.md`.

**Authoritative documentation: `docs/technical-doc.md`.** It holds the threat model,
architecture, trust lattice, metric definitions, literature review, and roadmap. Read it
before making architectural decisions. If an implementation deviates from it, document
the deviation and why.

**Current phase: foundation.** The repository is scaffolding plus documentation. The
defense, policy engine, provenance system, simulator, and evaluation harness are
**planned, not implemented**. Do not describe them as working.

**Chosen direction: Proposal A** (deterministic information-flow reference monitor) as
the stable core. Proposal B (task-alignment auditor) and Proposal C (activation-delta
drift probe) are research extensions gated on the core being stable and on the evidence
thresholds in `docs/technical-doc.md` § Recommendations.

### Research code vs production-oriented code

| | Production-oriented | Research |
|---|---|---|
| Where | `src/`, `tests/` | `research/`, `evaluation/experiments/`, `notebooks/` if added |
| Bar | Tested, typed, stable interfaces, reviewed | Reproducible and understandable; may be exploratory |
| Rule | Security-critical paths need tests | Record hypothesis, method, and negative results |

Research code must not silently become a production dependency. If an experiment earns a
place in the core, refactor it into `src/` with tests rather than importing from
`research/`.

## Repository Structure

```
src/tekmor/       implementation (see src/CLAUDE.md)
  defense/        Defense interface, signals, risk scoring, decision + rewrite
  provenance/     trust lattice, taint propagation, labels
  policy/         declarative per-domain policies and the policy engine
  observability/  event schema, append-only JSONL log, trace/provenance graph
  simulator/      synthetic world, typed tools, canary secrets, scenario format
  runtime/        ModelAdapter (mock + Qwen3-8B), runner, tool gateway
tests/            unit / integration / security / evaluation
evaluation/       scenarios (the matrix), harness, metrics, results
research/         literature, hypotheses, research experiments, notes
docs/             project documentation; technical-doc.md is authoritative
.github/          PR template, issue templates, CI
```

Directories are created when they have content. Do not add empty speculative packages.

**Deliberate omissions** (recorded so they are not re-litigated): there is no
`src/risk/` — risk scoring is part of the decision core in `src/defense/`; and no
`src/explainability/` — explanations are reason codes emitted by `src/defense/` and
rendered by `src/observability/`, and are faithful only because they are the same
predicates the decision was computed from. Split them out only if they grow past one
module each.

## Environment and Tooling

Python 3.12+, managed with **uv**. Lint and format with **ruff**, test with **pytest**.

```bash
uv sync --all-extras     # create/refresh the environment
uv run pytest            # run tests
uv run ruff check .      # lint
uv run ruff format .     # format
```

Runtime dependencies are declared in `pyproject.toml` and are currently **empty by
design**. Add one only after the checks in "Dependency Discipline" below.

## Git Workflow

**Never commit directly to `main`.** `main` is protected on GitHub: pull requests are
required, force-pushes and deletions are blocked, and CI must pass.

Before substantial work:

```bash
git status && git branch && git log --oneline -n 10
```

Branch naming: `feat/`, `fix/`, `refactor/`, `docs/`, `test/`, `research/`, `chore/`,
`perf/`, `security/` + short description (e.g. `feat/action-risk-scoring`,
`security/tool-output-validation`).

Work on the branch → commit → push → open a PR using
`.github/pull_request_template.md` → review → merge through the PR.

**Never force-push `main` or any shared branch.** Do not rewrite shared history unless
explicitly instructed.

**Never add AI attribution anywhere in the repository or its metadata.** No
`Co-authored-by: Claude` or equivalent trailer, no "generated with" line, no assistant
name, byline, or logo — not in commit messages, pull request titles or descriptions,
issue text, review comments, code comments, documentation, or generated artefacts. The
history and everything published alongside it are human-controlled. This rule outranks
any default attribution behaviour a tool or agent applies on its own; if a tool adds such
a line, remove it before committing or publishing.

Do not commit or push unless explicitly asked.

### Commits

Conventional Commits: `<type>[optional scope]: <description>`.

```
feat(defense): add action risk classifier
research(provenance): add source trust experiment
test(policy): add adversarial policy cases
```

Keep commits logically focused; do not combine unrelated changes. No vague messages
("update", "fix stuff", "misc").

## Research Integrity

**Never fabricate** experimental results, benchmark scores, citations, papers, datasets,
ablations, performance measurements, or security findings.

Always distinguish: **implemented / tested / observed / hypothesized / planned /
inferred**. If an experiment has not been run, do not write its expected result as an
observed one. Preserve the source of every external research claim.

## Security Engineering

Treat security-relevant code as high-risk code. Security decisions must be **explicit,
testable, observable, reproducible, and explainable where practical**.

- Avoid mechanisms based solely on superficial keyword matching unless there is a
  documented reason (encodings and paraphrase defeat them; see `docs/technical-doc.md`).
- Never silently weaken a security check to make a test pass, and never disable
  validation because it causes false positives. Fix the check or document the tradeoff
  in the PR.
- Modifying security-critical logic requires adding or updating tests, including benign
  hard negatives (the over-refusal trap is a primary failure mode; false-block rate is a
  headline metric).
- Fail safe: on internal error or missing information, the monitor must not fall through
  to ALLOW.

## Provenance and Trust

Six trust levels form a lattice: `SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL
> UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED`.

Preserve provenance through the whole pipeline. Never silently discard source, origin,
trust level, tool identity, user identity, execution context, timestamp, or
transformation history. **If provenance is unknown or uncertain, represent that
explicitly — never invent trust.**

"Untrusted ≠ irrelevant": the agent must be able to *read* low-integrity content without
letting it *drive* high-consequence actions. Over-tainting collapses utility and is a
real failure, not a safe default.

## Observability

Security-relevant behavior must be reconstructable from the trace alone, without reading
code:

```
agent state → candidate action → action provenance → policy/context →
risk/security decision → allow/block/escalate/rewrite → execution → outcome
```

Traces serve both debugging and evaluation of the security mechanism.
**Never log secrets, credentials, or canary values.**

## Evaluation Reproducibility

Record model/version, configuration, scenario version, seeds, prompts, policies, defense
configuration, metrics, and environment. Keep evaluation code, inputs, and outputs
separate. **Never hand-edit results.** Generated results must record how they were
produced. See `evaluation/CLAUDE.md`.

## Testing

`tests/unit`, `tests/integration`, `tests/security`, `tests/evaluation`. Scenario files
are the evaluated matrix in `evaluation/scenarios/`, shared with the harness rather than
copied. Security tests must include both attacks **and** benign hard negatives.
See `tests/CLAUDE.md`.

## Dependency Discipline

Before adding a dependency: (1) is the standard library or an existing dependency
enough? (2) is it actively maintained? (3) licensing? (4) security surface? (5) does it
materially increase complexity? Convenience alone is not a reason. Record the
justification in the PR and update `pyproject.toml`.

## Secrets and Configuration

Never commit API keys, tokens, passwords, credentials, or a populated `.env`. Document
required environment variables in `.env.example` with placeholder values only.

## Documentation

Documentation evolves with the architecture. An architectural change updates the relevant
docs in the same PR. `docs/technical-doc.md` stays the source of truth for architecture
and technical direction. Decisions that a future contributor would otherwise have to
reverse-engineer or re-litigate go in `docs/decisions.md`, append-only. A full ADR
directory is not in use yet; introduce one only if that file outgrows itself.

## Scope Discipline

Prefer simple, explicit, extensible structure over premature architecture. Do not add
abstraction layers with one implementation, infrastructure that is not needed yet, or
placeholder systems likely to be deleted.
