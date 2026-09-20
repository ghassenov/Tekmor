# Architecture

How Tekmor is put together, and why it is shaped this way.

For the threat it addresses, see [threat-model.md](threat-model.md). For how trust is
tracked, see [provenance.md](provenance.md). For how any of this is measured, see
[evaluation.md](evaluation.md).

---

## The one idea

An LLM agent reads things — emails, web pages, invoices, tool results — and then acts.
The danger is that reading and acting are not separated: text the agent read can end up
*driving* what it does. An attacker who can put text where the agent will read it can, in
effect, issue commands.

Tekmor's answer is a single rule applied everywhere:

> **Untrusted content is evidence, not authority.**

The agent may *read* anything. What that content is not allowed to do is *authorise* a
consequential action. Reading a hostile invoice is fine; letting that invoice decide who
gets paid is not.

This is deliberately not a prompt-injection detector. Detectors classify text as
malicious or benign, and the literature is consistent that adaptive attackers defeat them
— rephrase, encode, translate, and the classifier misses. Tekmor instead constrains
*what an action is allowed to do given where its influences came from*, which does not
depend on recognising the attack.

## The reference monitor

Every candidate tool call passes through one function:

```python
Defense.decide(state, action, provenance, policy) -> Decision
```

Four things go in:

| Input | What it is |
|---|---|
| `state` | What the agent is doing: the authenticated user's task, the step number |
| `action` | The tool call being proposed, with its arguments |
| `provenance` | Every source the agent has read so far, with its trust label |
| `policy` | The deployment's rules: which tools are sensitive, what may be downgraded |

One `Decision` comes out, carrying a verdict, the reason codes that produced it, and a
risk score.

This is a **reference monitor** in the classical sense, and it is meant to satisfy the
classical properties:

- **Complete mediation** — no path to a tool bypasses it.
- **Tamper resistance** — the monitor's own policy and thresholds carry the highest trust
  label and are never writable by content the agent observed.
- **Fail closed** — an internal error, a missing signal or unknown provenance never
  degrades to "allow". `mediate()` converts any exception into `BLOCK` with an
  `INTERNAL_ERROR` reason code.

![Tekmor decision flow](../assets/decision-flow.svg)

## The four verdicts

Most defenses are binary: allow or block. "Block everything" is a real failure mode — a
security layer that stops legitimate work gets switched off. Tekmor has four outcomes so
that safety and usefulness are not forced into one trade.

| Verdict | Meaning |
|---|---|
| `ALLOW` | The call runs as proposed. |
| `BLOCK` | The call does not run. |
| `ESCALATE` | Deferred to a human. In evaluation there is no human, so it counts as a refusal. |
| `REWRITE` | The call is replaced by a lower-impact equivalent, and *that* runs. |

`REWRITE` is the interesting one. Risky tools are mapped to reversible siblings along an
impact-ordered capability lattice: `send_email` becomes `draft_email`,
`execute_payment` becomes `prepare_payment`, `delete` becomes `create_review_task`. The
task keeps moving and a human still sees the result, but the irreversible effect is
removed. This is least privilege applied per action rather than per session.

## How a decision is computed

The rules run in a fixed order, and the first one that fires decides:

1. **Least privilege** — is this tool allowed for this task at all? If not, `BLOCK`.
2. **Permitted-Flow** (confidentiality) — would this call send data somewhere its
   sensitivity label forbids? If so, `BLOCK`.
3. **Trusted-Action** (integrity) — is this a *sensitive* action whose influences fall
   below the integrity threshold? If so, `REWRITE` when the policy names a vetted
   downgrade, otherwise `ESCALATE`.
4. Otherwise `ALLOW`.

The predicates are evaluated once into a named `Signals` value. The monitor decides from
that value, and the risk score is computed from the same value — so the number reported
beside a verdict was derived from exactly the facts the verdict was.

### The risk score describes; it does not decide

This is a deliberate design decision, recorded in [decisions.md](decisions.md).

A weighted sum that could overrule an auditable policy would be a worse trade than a
score that only reports. So the rules decide, in their fixed order, and `risk.band()` is
a *claim about the rules* — every verdict must land in the band of its own score — which
is asserted by test across the whole scenario matrix. A severity that lands in the wrong
band is a test failure, not a dashboard curiosity.

The severities are **ordinal**. Their ordering is meaningful (so AUROC is), their
magnitudes are not yet probabilities (so ECE is reported, not claimed).

## Layers, and the rule they obey

Two components wrap the core rather than being inlined into it:

- **`CanaryScanner`** — an encoding-aware scan for secret values in outbound arguments.
  The provenance rule decides from labels, so a secret that reaches an argument without
  passing through a labelled observation is invisible to it. The scanner covers that
  residual. It matches across base64, hex, spaced and reversed encodings, because a
  metric defined only on the plain form would not be measuring exfiltration.
- **`AlignmentAuditor`** — an optional LLM judge for the *gray zone*: actions the rules
  allowed although something below the integrity threshold influenced them.

Both obey one invariant, **monotone-safe fusion**:

> A probabilistic sensor may only *raise* suspicion. It may never soften a verdict the
> deterministic core produced.

A sensor false negative therefore cannot weaken the guarantee; it can only fail to add
one. Anything the core did not allow never reaches the judge at all.

## Package layout

```
src/tekmor/
  defense/        the decision contract, signal extraction, risk scoring, the monitor,
                  the capability downgrade, the canary layer, the alignment auditor
  provenance/     the trust lattice, taint propagation, endorsement, the canary matcher
  policy/         the declarative per-domain policy object and its three predicates
  observability/  the event schema, the append-only JSONL log, the timeline viewer
  simulator/      three synthetic worlds, typed tools, canary-tagged secrets, scenarios
  runtime/        the model adapter (mock and Qwen3-8B), the run loop, the tool gateway
```

Two omissions are deliberate and recorded so they are not re-litigated: there is no
`src/risk/`, because risk scoring must be computed from the same signals the decision
uses and therefore belongs beside it; and no `src/explainability/`, because explanations
are reason codes emitted by the decision core and rendered by observability — they are
faithful precisely because they *are* the predicates the decision was computed from,
rather than a rationalisation generated afterwards.

## Explainability by construction

Reason codes are the literal predicates that fired —
`source=ADVERSARY_CONTROLLED`, `external_transmission=true`,
`provenance_touches_untrusted=true`. There is no post-hoc natural-language rationale, and
that is the point: a generated explanation can be wrong about its own decision, whereas a
reason code cannot be, because it is the decision.

Coarse reason codes are public; fine-grained sub-scores stay in the private trace. A
public score is a hill-climbing channel for an attacker, which the adaptive-attacker
experiment treats as a real capability rather than a hypothetical one.

## Observability

Every decision emits an event to an append-only JSONL log. The requirement is that
security-relevant behaviour is reconstructable from the trace alone, without reading the
code:

```
agent state -> candidate action -> action provenance -> policy/context ->
risk/security decision -> allow/block/escalate/rewrite -> execution -> outcome
```

`observability/viewer.py` renders a timeline and a provenance graph from the log alone.
The log records argument *names*, never argument *values*, and never secrets or canary
tokens.
