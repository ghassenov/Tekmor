# CLAUDE.md — tests/

Scope: automated tests. Root rules apply.

## Categories

| Directory | Purpose |
|---|---|
| `unit/` | individual functions and classes; fast, no I/O, no model calls |
| `integration/` | interaction between components (runtime → defense → gateway → log) |
| `security/` | adversarial and security-sensitive behavior |
| `evaluation/` | the benchmark/evaluation infrastructure itself, not research results |
| `fixtures/` | reusable inputs and controlled datasets |

Create a directory when it has its first test; do not pre-create empty ones.

## Rules

- **Security tests must include both attacks and benign hard negatives.** Testing only
  obvious attacks measures nothing about the over-refusal trap, and false-block rate is a
  headline metric. Cover the seven attack families and difficulty levels 1–5 from
  `docs/technical-doc.md` Part I as coverage grows.
- **Test the mechanism, not the wording.** Include paraphrase and encoding variants
  (base64/hex/spaced/reversed) and reordered fragments for compositional cases. A test
  that passes only against one phrasing hides overfitting.
- **Never weaken a security check to make a test pass**, and never delete or skip a
  security test to get green. If a check is genuinely wrong, fix the logic and explain it
  in the PR.
- A failing security test is a finding. Mark it `xfail` with a reason and an issue link
  rather than silently removing it.
- Tests are deterministic: fixed seeds, the mock `ModelAdapter`, no network. Tests that
  need a real model or a GPU are marked and excluded from the default run.
- Fixtures are data files, not code that computes expected answers from the
  implementation under test.
- Changing security-critical logic in `src/` requires adding or updating tests here in the
  same PR.
