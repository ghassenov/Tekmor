# CLAUDE.md — src/

Scope: production-oriented implementation. Root rules still apply. Component-specific
rules live in `defense/`, `provenance/`, `policy/`, and `observability/`.

## Status

Scaffolding. The packages below define the module boundaries from
`docs/technical-doc.md` Part IV; the components themselves are **not implemented**.

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
