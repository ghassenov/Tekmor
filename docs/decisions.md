# Decision Log

Append-only record of decisions that shape the project. Newest last. One entry per
decision: what was decided, why, what was rejected, and what would reopen it.

This is deliberately a single file rather than an ADR directory — the volume of decisions
does not yet justify one. If entries here grow past a few dozen, split them into
`docs/adr/` at that point (which is itself a decision to record here).

Scope: decisions a future contributor would otherwise have to reverse-engineer or
re-litigate. Routine implementation choices do not belong here.

---

## 2026-09-18 — Proposal A as the core direction

**Decided.** Build the deterministic information-flow reference monitor (Proposal A in
`technical-doc.md`) as the stable core. Proposal B (task-alignment auditor) and
Proposal C (activation-delta drift probe) are research extensions layered on top, never
replacements.

**Why.** Highest security, legibility, and feasibility of the three; CPU-only for the
defense itself; deterministic and therefore resistant to the adaptive attacks documented
as breaking classifier-based defenses. `technical-doc.md` § Recommendations reaches this
conclusion directly.

**Rejected.** Starting with B or C. Both depend on the deterministic core carrying the
security guarantee; building either first would produce a defense whose reliability rests
on a probabilistic signal.

**Reopens if.** BTU falls below ~0.7 on benign and hard-negative scenarios — at which
point a FIDES-style endorsement primitive comes before any new signal (same source).

---

## 2026-09-18 — Python 3.12+ with uv, ruff, and pytest

**Decided.** `pyproject.toml` managed by uv (with `uv.lock` committed), ruff for lint and
format, pytest for tests, hatchling as the build backend, `src/` layout.

**Why.** Single lockfile and one tool for environment and dependency management; ruff
replaces a separate linter and formatter. Reproducibility of the environment is a
prerequisite for reproducible evaluation, so the lockfile is committed.

**Rejected.** Poetry (heavier, no gain here) and plain pip with requirements files
(weaker reproducibility).

---

## 2026-09-18 — No runtime dependencies until a concrete need

**Decided.** `dependencies = []` in `pyproject.toml`. Dev group is `pytest` and `ruff`
only.

**Why.** The dependency-discipline checklist in `CLAUDE.md` applies from the first
dependency, not retroactively. Adding YAML, validation, or serving libraries before the
code that needs them would pre-commit the architecture to them.

**Reopens if.** A component genuinely needs one — justified in the PR that adds it.

---

## 2026-09-18 — No `src/risk/` or `src/explainability/` packages

**Decided.** Risk scoring lives in `src/tekmor/defense/` as part of the decision core.
Explanations are reason codes emitted by `src/tekmor/defense/` and rendered by
`src/tekmor/observability/`.

**Why.** Explanations are faithful *only because* they are the same predicates the
decision was computed from. Putting explanation behind its own module boundary invites a
separate explanation path, which is exactly the post-hoc rationalization the design
rejects. Risk scoring is likewise inseparable from the decision it produces.

**Rejected.** Mirroring the generic scaffold that lists `risk/` and `explainability/` as
peers of `defense/`.

**Reopens if.** Either grows past roughly one module, at which point they can be split
out while keeping a single computation path.

---

## 2026-09-18 — MIT license retained

**Decided.** Keep the MIT license already present in the repository.

**Why.** Already committed, and compatible with the projects Tekmor builds on or
integrates with (AgentDojo is MIT, as are several reference implementations).

**Rejected.** Apache-2.0, suggested in `technical-doc.md` Part III "to match most
dependencies". Its patent grant would matter more if the project were contributed to or
built on by organizations; it is not worth relicensing for now.

---

## 2026-09-18 — `main` protected on GitHub, enforced for admins

**Decided.** Branch protection on `main`: pull requests required, 0 required approvals,
required status check `lint and test`, strict (branch must be current), force-pushes and
deletions blocked, conversation resolution required, `enforce_admins: true`.

**Why.** The "never commit directly to `main`" rule should be enforced by the platform
rather than by agent instructions alone. Zero required approvals keeps a single
maintainer able to self-merge; `enforce_admins: true` keeps the rule binding on that
maintainer, which is the only way it means anything on a solo repository.

**Rejected.** Requiring one approving review (unmergeable by a single maintainer), and
documentation-only enforcement (not binding).

**Reopens if.** The protection blocks an emergency fix — it is reversible in repository
settings, and disabling it should be recorded here.

---

## 2026-09-18 — CI is one lint-and-test job

**Decided.** A single GitHub Actions job running `ruff check`, `ruff format --check`, and
`pytest -m "not slow"` on pull requests and pushes to `main`.

**Why.** It is the minimum that makes the required status check meaningful. The project's
real CI needs — evaluation runs, GPU jobs for activation extraction, scenario matrices —
are not known yet, and building that pipeline now would mean guessing.

**Rejected.** Matrix builds, coverage gates, and scheduled evaluation runs, all premature.

**Reopens if.** The evaluation harness lands and its runs need to be automated.

---

## 2026-09-18 — The defense fails closed at a single mediation point

**Decided.** Callers never invoke `Defense.decide` directly; they go through
`tekmor.defense.core.mediate()`, which converts an exception or a malformed return value
into `BLOCK` with reason code `INTERNAL_ERROR` / `MALFORMED_DECISION`. Relatedly, the
meet of an empty set of provenance sources is `ADVERSARY_CONTROLLED`, not the top of the
lattice.

**Why.** "Fail safe: on internal error or missing information, the monitor must not fall
through to ALLOW" is a property of the *system*, not of each defense implementation. One
wrapper makes it hold for every defense, including future ones and research prototypes,
and it is testable in isolation. Unknown provenance is missing information, so it takes
the same treatment.

**Rejected.** A try/except inside each defense (repeated, and a new defense silently
opts out) and a decorator on `decide` (same problem, plus it can be forgotten).

**Reopens if.** Escalation to a human turns out to be the better failure mode for some
error classes — that is a decision about *which* safe verdict, not about failing closed.

---

## 2026-09-18 — Tool sensitivity lives on the policy, not on the tool

**Decided.** `Policy.sensitive_tools` names the tools a domain treats as sensitive. Tool
definitions in the simulator will carry their capability *variants* (for the rewriter),
but which calls count as sensitive is policy.

**Why.** The same `send_email` is routine in one deployment and restricted in another;
binding sensitivity to the tool definition would make per-domain policies unable to
differ, which is the thing per-domain policies are for.

**Rejected.** A `sensitivity` field on the tool spec, and a global registry of sensitive
tool names.

**Reopens if.** The capability lattice needs an intrinsic impact ordering per tool that
policies only narrow — then both exist and this entry says where each lives.

---

## 2026-09-18 — The event log records argument names, never argument values

**Decided.** `DecisionEvent` carries the tool, the argument *names*, the source ids, the
action's integrity, the verdict, and the reason codes. Argument values are not written.

**Why.** "Never log secrets, credentials, or canary values." There is no canary registry
yet to redact values against, and a log that is safe only as long as a redactor is
correct is a worse default than one that cannot leak. Names are enough to reconstruct
which call was decided on.

**Reopens if.** The simulator's canary registry lands and the trace genuinely needs
values for debugging — at which point values go through redaction against the registry,
and the reason codes stay value-free regardless (they are public, per Part VIII).
