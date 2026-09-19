# CLAUDE.md — src/

Scope: production-oriented implementation. Root rules still apply. Component-specific
rules live in `defense/`, `provenance/`, `policy/`, and `observability/`.

## Status

The packages below define the module boundaries from `docs/technical-doc.md` Part IV.

**Implemented:** the decision contract (`Action`, `ActionProvenance`, `AgentState`,
`Decision`, `Verdict`, the `Defense` protocol) and the fail-closed `mediate()` entry
point in `defense/core.py`; the three baselines in `defense/baselines.py`; the
`ReferenceMonitor` in `defense/monitor.py`, with the capability downgrade; signal
extraction in `defense/signals.py` and the risk score, its severities and its bands in
`defense/risk.py`; the `Policy` object and the Trusted-Action, Permitted-Flow and
least-privilege rules in `policy/core.py`; the trust lattice, `Source`, its confidentiality label and the
`TaintTracker` in `provenance/`; the encoding-aware canary matcher in
`provenance/canary.py` and the `CanaryScanner` layer over it in `defense/canary.py`; the
decision event and append-only JSONL log in `observability/events.py` and the timeline /
provenance-graph viewer in `observability/viewer.py`; the enterprise,
financial and SOC worlds, typed tools, canary tagging and the JSON/YAML scenario format
in `simulator/`; the `ModelAdapter` protocol, the scripted mock, the Qwen3-8B adapter,
the run loop and the `ToolGateway` in `runtime/`; the endorsement primitive
(`provenance/taint.py`, opt-in per policy) and Proposal B's `AlignmentAuditor`
(`defense/auditor.py`) with a local-LM judge (`runtime/qwen.py`), built and measured
and not adopted (`docs/decisions.md`).

**Not implemented:** argument redaction as a rewrite, and selective escalation — the
deferral half of CALIB-RISK, which would give the score authority over a verdict and is
declined in `docs/decisions.md`. The severities in `defense/risk.py` are still ordinal:
Platt-scaling them against held-out scenarios is implemented and *measured*
(`evaluation/calibration.py`), and on the full twenty-four-scenario matrix it improves
ECE (0.07 -> 0.04) where on seven it made it worse — while still costing a little ranking
— so the scale in use remains the hand-ordered one. ECE is measured and reported, not
achieved.

**Evaluated, on this repository's own matrix.** `evaluation/harness.py` runs every
scenario under every defense and scores BTU, ASR, CVR, FBR and UER from world state,
plus precision/recall/F1 over per-action labels and AUROC/AUPRC/ECE over the risk score,
and Platt-scales that score leave-one-scenario-out to measure whether its magnitudes are
probabilities. It also reports the pass/fail grid by attack family and difficulty level.
`docs/decisions.md` records each measurement and its limits. Twenty-four scenarios in
three domains, covering the seven attack families at levels 1-5, is a matrix, not a
benchmark: the robustness variants, ablations, adaptive attacker and AgentDojo run live in
`evaluation/`. On AgentDojo, call-level taint costs benign utility down to the
`deny-sensitive` baseline on three suites of four (`docs/decisions.md`).

A scenario states its own ground truth (`success` / `attack_success`: conditions over
world state) and its place in the matrix (`family`, `level`), and all of it, like `id`
and `benign`, never reaches a defense. The *per-action*
labels the detection metrics need are not stated at all: `evaluation.metrics.unsafe_steps`
derives them by replaying each prefix undefended, so no one hand-labels which step the
defense was supposed to stop.

**What the risk score is and is not.** `defense/signals.py` evaluates the policy
predicates once into a named `Signals` value; the monitor decides from it and
`defense/risk.py` scores the same object, so the number next to a verdict was computed
from the facts that verdict was. The score *describes*, it does not decide — the rules do,
in their fixed order — and `risk.band()` states the doc's threshold table as a claim about
the rules that `tests/security/test_risk_bands.py` asserts over the whole matrix. The
severities are ordinal, so their ordering (AUROC) is meaningful and their magnitudes
(ECE) are not yet.

**What taint propagation does and does not close.** The sources the monitor decides from
are now computed from what the agent actually read: the world labels stored content, a
tool call returns that label with its result, and `TaintTracker` accumulates it over the
run. Nothing declares a step's provenance any more, so a verdict on a scenario is
evidence about the whole path rather than about hand-written labels.

**What the canary scanner does and does not close.** The provenance rule decides from
labels, so a secret that reaches an argument without passing through a labelled
observation — a token pasted into an internal page nobody marked confidential — is
invisible to it. `defense/canary.py` layers an argument scan over any defense for exactly
that residual, and `provenance/canary.py` is the encoding-aware matcher both it and the
CVR ground truth use, so the metric is defined across encodings as
`docs/technical-doc.md` says it is. It is a text matcher and is layered rather than
inlined for that reason: it may only raise a verdict, never soften one, and it scans the
call that would execute, so a capability downgrade is not undone by it. It reads
arguments, so a value routed through world state (the financial domain's prepared
payment) is outside it.

What remains is the *granularity*. Influence is call-level and prefix-monotone — every
observation the agent has seen taints every later action — so a benign action taken
after reading one hostile document is labelled by that document. That is the
conservative direction and the utility cost is real; the benign half of each scenario
pair is what measures it. Argument-level attribution is now implemented behind
`Policy.argument_provenance`, measured, and **off**: on AgentDojo it raises BTU 0.45 ->
0.55 and ASR 0.04 -> 0.07, and it lets a mislabelled `trusted` source vouch for an
attacker's value where the call-level meet used to hide the labelling error
(`docs/decisions.md`). Field-level labels *inside* one observation, and provenance for a
value laundered through world state into a handle, are the remaining upgrades.

## Layout

| Package | Responsibility |
|---|---|
| `defense/` | `Defense` interface, signal extraction, risk scoring, decision + rewrite |
| `provenance/` | trust lattice, taint propagation through memory and tool-output fields |
| `policy/` | declarative per-domain policies and their deterministic evaluation |
| `observability/` | event schema, append-only JSONL log, timeline and provenance graph |
| `simulator/` | synthetic world, typed tools, canary-tagged secrets, scenario format |
| `runtime/` | `ModelAdapter` (mock + Qwen3-8B), runner, tool gateway |

## Rules

- **Maintain modular architecture with clear interfaces.** The pipeline stages
  (provenance → signals → policy → decision → observability) communicate through
  explicit typed data, not shared mutable globals. A stage must be testable alone.
- **Avoid unnecessary coupling.** `simulator/` and `runtime/` must not import from
  `defense/` internals; the defense sees only the state, action, provenance, and policy
  it is handed. Evaluation code depends on `src/`, never the reverse.
- **The defense must never depend on scenario identifiers, filenames, or known expected
  outcomes.** A defense that recognizes test cases is not evidence of security. This is
  the single most important correctness rule in this tree.
- **Preserve provenance and observability.** Any transformation of an observation or a
  tool result carries its provenance forward. Every decision emits a trace event.
- **Keep security decisions explicit and inspectable.** The decision must be computed
  from named signals, and the reason codes must be those same signals — that is what
  makes the explanation faithful rather than a post-hoc rationalization.
- **Write tests for security-critical behavior**, including benign hard negatives.
- **Do not embed experimental logic in production components** without justification.
  Research code lives in `research/`; promote it by refactoring, not by importing.
- Type-annotate public interfaces. Prefer plain dataclasses and stdlib types until a
  concrete need justifies a dependency.
- **Optional dependencies are imported inside the component that needs them**, never at
  module import time, and are declared as an extra in `pyproject.toml` (`yaml`, `qwen`).
  `dependencies = []` stays true for a checkout that does not use those components.
