# CLAUDE.md — src/

Scope: production-oriented implementation. Root rules still apply. Component-specific
rules live in `defense/`, `provenance/`, `policy/`, and `observability/`.

## Status

The packages below define the module boundaries from `docs/technical-doc.md` Part IV.

**Implemented:** the decision contract (`Action`, `ActionProvenance`, `AgentState`,
`Decision`, `Verdict`, the `Defense` protocol) and the fail-closed `mediate()` entry
point in `defense/core.py`; the three baselines in `defense/baselines.py`; the
`ReferenceMonitor` in `defense/monitor.py`, with the capability downgrade; the `Policy`
object and the Trusted-Action, Permitted-Flow and least-privilege rules in
`policy/core.py`; the trust lattice, `Source`, its confidentiality label and the
`TaintTracker` in `provenance/`; the encoding-aware canary matcher in
`provenance/canary.py` and the `CanaryScanner` layer over it in `defense/canary.py`; the
decision event and append-only JSONL log in `observability/events.py`; the enterprise,
financial and SOC worlds, typed tools, canary tagging and the JSON/YAML scenario format
in `simulator/`; the `ModelAdapter` protocol, the scripted mock, the Qwen3-8B adapter,
the run loop and the `ToolGateway` in `runtime/`.

**Not implemented:** signal extraction, calibrated risk scoring, and argument redaction
as a rewrite. Without a risk score there is no calibration, so precision/recall, AUROC and
ECE are still undefined here.

**Evaluated, on this repository's own matrix.** `evaluation/harness.py` runs every
scenario under every defense and scores BTU, ASR, CVR, FBR and UER from world state;
`docs/decisions.md` records the first measurement and its limits. Seven scenarios in
three domains is a matrix, not a benchmark, and the external validation (AgentDojo),
the robustness variants and the adaptive attacker are still ahead.

A scenario states its own ground truth (`success` / `attack_success`: conditions over
world state) and that, like `id` and `benign`, never reaches a defense.

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
pair is what measures it. Field-level provenance and argument-level attribution are the
upgrade, and they are not implemented.

## Layout

| Package | Responsibility |
|---|---|
| `defense/` | `Defense` interface, signal extraction, risk scoring, decision + rewrite |
| `provenance/` | trust lattice, taint propagation through memory and tool-output fields |
| `policy/` | declarative per-domain policies and their deterministic evaluation |
| `observability/` | event schema, append-only JSONL log, trace and provenance graph |
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
