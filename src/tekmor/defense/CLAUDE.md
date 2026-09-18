# CLAUDE.md — src/tekmor/defense/

Scope: the decision core — the reference monitor itself. Root and `src/` rules apply.

Owns: the `Defense` interface, signal extraction, risk scoring, and the
ALLOW / BLOCK / ESCALATE / REWRITE decision including capability downgrade.
Risk scoring and explanation live here (not in separate packages) because both must be
computed from the same signals the decision uses.

## Security invariants

These hold for every decision. Breaking one is a security bug, not a style issue.

1. **Complete mediation.** Every candidate action passes through `Defense.decide()`.
   No path to the tool gateway bypasses it.
2. **Tamper-resistance.** The monitor's own state, thresholds, and policies carry
   `SYSTEM_POLICY` trust and are never writable by content the agent observed.
3. **Fail safe, fail closed.** An internal error, a missing signal, or unknown provenance
   must never degrade to ALLOW. Escalate or block, and record why.
4. **Monotone-safe fusion.** A probabilistic sensor (task-alignment auditor, activation
   drift probe) may only *raise* suspicion. It must never downgrade a BLOCK produced by
   the deterministic core, so a sensor false negative cannot weaken the guarantee.
5. **No scenario awareness.** Decisions depend only on agent state, candidate action,
   provenance, policy, and observed content — never on scenario IDs, filenames, or
   expected outcomes.

## Risk scoring

- The score is computed from the same `Signals` value the decision is, and it **reports**
  rather than decides: `ReferenceMonitor` reaches its verdict from the rules in their
  fixed order, and a weighted sum must never be able to overrule one. Weights nobody can
  audit replacing a policy anyone can is the failure mode to avoid.
- `risk.band()` is therefore a *claim* about the rules — every verdict must fall in the
  band of its own score — and it is asserted by test on the whole scenario matrix. A new
  severity that lands in the wrong band is a test failure, not a dashboard oddity.
- Severities are ordinal, not probabilities. Report ECE; do not call the scale calibrated
  until it has been scaled against held-out runs.
- A secondary sensor may only raise the score, exactly as it may only raise the verdict
  (invariant 4). `CanaryScanner` is the existing example.
- The **aggregate** score is public and belongs in the trace; the per-signal
  contributions (`risk.contributions`) are the private half, for the same reason coarse
  reason codes are public and fine-grained ones are not.

## Action decisions

- The four outcomes are policy/action control, not classification labels. REWRITE is a
  least-privilege downgrade along an impact-ordered capability lattice (send → draft,
  execute_payment → prepare_payment, delete → create_review_task, plus argument
  redaction). ESCALATE is deferral to a human, not a soft block.
- REWRITE exists to preserve utility: "block everything" is a failure mode, and
  false-block rate is a headline metric.
- Deterministic core first. Probabilistic signals are secondary and clearly separated in
  the trace.

## Explainability

- Reason codes must be the literal predicates that fired (e.g.
  `source=ADVERSARY_CONTROLLED`, `external_transmission=true`,
  `provenance_touches_untrusted=true`). Faithful by construction; do not generate
  post-hoc natural-language rationales as the explanation of record.
- Expose **coarse** reason codes publicly; keep fine-grained sub-scores in the private
  trace. Public reason codes are an attacker's hill-climbing channel.
- **Never** include secret values or canary tokens in an explanation.

## Adversarial testing

- Any change here needs tests in `tests/security/` covering both attacks and benign hard
  negatives, across the seven attack families in `docs/technical-doc.md` Part I.
- Test robustness variants (paraphrase; base64/hex/spaced/reversed encodings; reordered
  fragments), not just one wording of an attack.
- Never weaken a check to make a test pass. If a check is wrong, fix the logic and say so
  in the PR.
