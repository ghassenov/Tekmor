# CLAUDE.md — src/tekmor/policy/

Scope: declarative policies and their deterministic evaluation. Root and `src/` rules
apply.

## Rules

- **Policies are data, not code.** Per-domain policies are declarative and versioned, so
  a decision can be replayed against the exact policy that produced it. Every trace event
  records the active policy ID and version.
- **Evaluation is deterministic and total.** Same inputs → same decision, with no model
  call, no clock, and no network in the evaluation path. An unmatched case has a defined
  outcome; it is never an implicit ALLOW.
- Two policy classes from `docs/technical-doc.md` Part IV:
  **Trusted-Action** (a sensitive tool may only be driven by inputs whose minimum
  integrity ≥ threshold) and **Permitted-Flow** (confidential/canary data may not reach
  an outbound argument unless the recipient is authorized). Keep them distinct and
  separately testable.
- **Least privilege by default.** A tool is not permitted because it was not mentioned.
- **Policy is `SYSTEM_POLICY`-trusted state.** Nothing the agent observes may modify it.
  Policy loading must be inert — no executable policy formats, no eval.
- **Widening is a reviewed change.** Automated or model-proposed policy updates may only
  shrink the permitted space; widening it requires explicit human approval and a PR that
  says what it opens up.
- Each rule emits a reason code identifying itself. A rule that fires invisibly cannot be
  audited.
