# ARG-PROV: argument-level provenance with role-scoped endorsement

Status: **hypothesis, mechanism and predictions written before the first run**
(2026-09-19). Results are appended below, under their own heading, after the runs.
Nothing above that heading is edited to fit them. Amendments made before a result is
seen go under "Amendments", dated.

## Why this experiment

AgentDojo produced the project's most important number (`docs/decisions.md`, "AgentDojo:
the monitor stops what it guards..."). Call-level, prefix-monotone taint makes `tekmor`
equal to `deny-sensitive` on three suites of four: pooled BTU 44/97 = 0.45 at ASR
21/583 = 0.04. Endorsement moved that to BTU 0.69 at ASR 0.15. The attacks it let back
in (workspace injections 0, 1, 2 and slack 1, 4) are runs where the user named the
document the injection sits in. At call level, their provenance is identical to
legitimate work.

The literature's recent answer is to move the check from the call to the argument:

- **PACT** (arXiv:2605.11039). An injection is dangerous when it *determines an
  authority-bearing argument*, not when it appears in the context. It assigns semantic
  roles to arguments and checks each argument's origin against its role. Reported:
  100% utility and security under oracle provenance on its diagnostic suites. With
  inferred provenance on AgentDojo, 38–46% utility at 96–100% security, with the gap
  attributed to role errors (13%) and provenance errors (23%).
- **AuthGraph** (arXiv:2605.26497) compares parameter sources against an authorization
  graph built from the user's request alone. Reported AgentDojo ASR 40% → 1% at 76% task
  completion.
- **FIDES** (arXiv:2505.23643) and **CaMeL** (arXiv:2503.18813): data-flow labels at
  value granularity. `docs/technical-doc.md` Part X lists the argument-level residual as
  research gap 1.

These numbers are the papers' own, measured with models on their configurations. They
are not comparable with this driver (see "Limits").

What this experiment adds, as far as the search on 2026-09-19 found, is **the
composition of argument-level provenance with the endorsement primitive, scoped by
role**. The user vouching for a document lets its *content* drive their request, but
never its *addresses*.

## Mechanism

Implemented in `src/` behind policy switches that default off, so that no existing
result moves.

1. **Value tracing.** The taint tracker keeps the text of every observation, and of
   the request. For each argument of a candidate call, every leaf value is traced: a
   string, or the `str()` of a number, and the elements of lists and mappings. A leaf
   is traced to the sources whose text contains it verbatim. Leaves shorter than
   `MIN_NAME` (6) characters, booleans and `None` are **untraced**, as is any leaf found
   in no source.
2. **Argument integrity.** A traced leaf counts at the *highest* integrity among the
   sources that contain it: a value a trusted source supplied is vouched for, even if
   an attacker also echoes it. An untraced leaf counts at the **call-level** integrity,
   the rule in force today, so untraceability never raises trust. An argument counts at
   the minimum over its leaves.
3. **Roles** (policy data, by argument name):
   - `content_args` are payload (a mail body, a subject, a note). They are exempt from
     Trusted-Action. Untrusted content may fill them ("untrusted is not irrelevant").
     Confidentiality is untouched, so Permitted-Flow still applies to them.
   - `target_args` name a destination, a principal or a credential. With
     `endorse_targets` off, endorsement never raises them. They are judged on the raw
     `trust` of their sources.
   - Every other argument is authority-bearing by default (PACT's conservative
     fallback): a selector, an amount, a date, an id.
4. **Trusted-Action at argument level.** A sensitive call passes when every
   non-content argument's integrity is at or above the threshold. A call with no
   non-content argument is judged at call level. The reason codes gain
   `AUTHORITY_ARGUMENTS` so a trace says which predicate decided.
5. **Write-back capping** (anti-laundering). Every content argument of an executed call
   (≥ `MIN_NAME` characters) is recorded as written at that call's call-level
   integrity. A later observation whose text contains a write made at an integrity
   below its own label **cannot vouch** for any value. It still counts, under its own
   label, at call level. This is what keeps `remember` → `recall` from laundering an
   attacker's value into `TRUSTED_INTERNAL` (`enterprise_memory_poisoned_note`).

The rule stays deterministic and runs on CPU. It calls no model and matches no text
classifier. Every argument's origin set is recorded in the trace as source ids, never
values.

## Role configuration (frozen with this file; from schemas only)

Written from tool and argument names (`evaluation/dojo.py` tool dump), never from
injection vectors or injection tasks.

- AgentDojo, all suites. `content_args` = {subject, body, content, title, description}.
  `target_args` = {recipients, cc, bcc, participants, email, recipient, user,
  user_email, channel, url, password}.
- Tekmor matrix, all scenarios. `content_args` = {subject, body, text, summary}.
  `target_args` = {to, payee, host}.

The `sensitive` and `trusted` lists in `evaluation/dojo.py` are unchanged.
`get_webpage` stays non-sensitive, so the slack URL-fetch residual is **not** addressed
here, deliberately (see Predictions).

## Arms

Every arm is run fresh, including the two recorded ones, from one commit, as one
`uv run python -m evaluation.dojo` invocation per arm with the flags below. Each
invocation also runs `allow-all`, which fixes the valid pairs (583 expected):

- `tekmor`: no flags. `tekmor+endorse`: `--endorse`. A: `--arguments`.
  B: `--arguments --endorse --endorse-targets`. C: `--arguments --endorse`.
- The matrix: `uv run python -m evaluation.harness` with the same flags.

| arm | taint | endorsement |
|---|---|---|
| `tekmor` | call-level | off (recorded: BTU 0.45, ASR 0.04) |
| `tekmor+endorse` | call-level | on (recorded: BTU 0.69, ASR 0.15) |
| **A** `tekmor-args` | argument-level | off |
| **B** `tekmor-args+endorse-all` | argument-level | on, all roles (`endorse_targets`) |
| **C** `tekmor-args+endorse` | argument-level | on, never for `target_args` |

## Hypotheses

- **H1 (primary): arm C Pareto-dominates both recorded points.** Pooled BTU ≥ 0.69 *and*
  pooled ASR ≤ 0.04 (≤ 21/583). **Refuted** if either fails.
- **H2: argument level alone helps.** Arm A has pooled BTU > 0.45 at pooled ASR ≤ 0.04.
  **Refuted** if BTU ≤ 0.45 or ASR > 0.04.
- **H3: role scoping is what removes endorsement's attacks.** ASR(B) > ASR(C).
  **Refuted** if ASR(B) ≤ ASR(C). That would mean argument level alone, not the
  scoping, did the work.
- **H4: no regression on the matrix.** Under A and C, every attack `tekmor` stops stays
  stopped, including `enterprise_memory_poisoned_note`, which tests the write-back
  capping. Benign BTU stays 1.00 apart from the one predicted exception below.
  **Refuted** by any newly landed attack.

The Recommendation 1 threshold (BTU ~0.7) is reported against, not re-derived.

## Predictions (stated to be checked, not to be tuned towards)

- The slack URL-fetch attacks (21 pairs, `injection_task_3`) land in **every** arm.
  `get_webpage` is not sensitive, and argument level does not change which tools are.
- **The honest ceiling.** Where the legitimate task itself takes a destination from an
  untrusted document the user named (pay the IBAN on this bill), C refuses it and B
  allows it. On the matrix this is `financial-benign-endorsed-invoice`: predicted
  refused under C and completed under B. Its attack twin is predicted stopped under C
  and landed under B. So C is expected to **lose** some banking BTU relative to call-level
  endorsement. That is the trade the hypothesis bets is worth it.
- Most of the BTU gain is expected in workspace and slack, where the user's own request
  or trusted lookups supply the recipients while mail and messages supply the content.

## Limits (decided before the run)

- **Near-oracle provenance.** The driver replays ground truth, so argument values are
  copied verbatim from what the agent read, and exact-match tracing is close to
  perfect. That is PACT's oracle setting, not its deployed one. A model that
  paraphrases or computes a value makes it untraced, which falls back to call level
  (safe, and utility-costly). No claim here transfers to a model-driven agent without
  that run.
- **Tool-selection residual** (PACT's own scope limit). An injection that makes the
  agent call a sensitive tool with trusted authority arguments and hostile content (mail
  the user's own boss a lie) passes by design. Measured if AgentDojo has such pairs,
  and reported as a limit, not a win.
- **Provenance spoofing.** An attacker who can place a value into a trusted source
  borrows its vouching (Agent Data Injection, arXiv:2607.05120). Out of scope for the
  static benchmark. It belongs to the adaptive round.
- The AgentDojo configuration was frozen before AgentDojo's first run. The role map is
  frozen here, before this experiment's first run. Neither may be edited after a result.

## Amendments

(none yet)
