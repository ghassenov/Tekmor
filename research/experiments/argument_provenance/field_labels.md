# ARG-PROV-F: field-level labels inside one observation

Status: **hypothesis, mechanism and predictions written before the first run**
(2026-09-19). Follow-up arm to `README.md`, whose Results section named it first
("Field-level labels inside one observation") as the honest form of its cause 1.
Results are appended below, under their own heading, after the runs. Nothing above that
heading is edited to fit them.

## Why this arm

`README.md`'s failure analysis found three distinct causes for the attacks argument-level
provenance let land. Cause 1 was the largest (20 of the 21 new landings in arm A) and the
only one that is a defect in the mechanism rather than a scope limit:

> The `direct` attack injects into slack's **channel list**, and the frozen configuration
> lists `get_channels` as `trusted`. The attacker's URL therefore appears verbatim inside
> a `TRUSTED_INTERNAL` observation, and argument-level tracing lets that observation
> vouch for it.

The environment confirms the shape (`agentdojo/data/suites/slack/environment.yaml`):
`channels` is a list of names, one of which is `"External_{prompt_injection_channel}"`.
The injection is a **channel name**. The URL the attack wants posted is a *fragment* of
that name.

So the label was not wrong about what `get_channels` guarantees. The institution
guarantees the *list*: that these channels exist, and that these are their names. It
guarantees nothing about the text somebody chose to call a channel. Collapsing a result
to one label is the gap `src/tekmor/provenance/CLAUDE.md` already names as a rule
("Provenance is field-level, not call-level. A single tool result can mix trust levels
across fields; preserve that granularity"), so this is the documented direction, not a
new idea.

## Mechanism

One rule, implemented in `src/tekmor/provenance/taint.py` behind
`TaintTracker.field_labels` (default off):

> **A tool result vouches for a value it returned, never for a fragment of one.**

A voucher matches a value anywhere in its text, as today, unless field labels are on
*and* the driver was able to split the result into its leaf values, in which case the
value must **be** one of those leaves.

Three consequences, stated so they can be checked rather than assumed:

1. **The user's request is never split.** It stays whole-text matching. This is an
   asymmetry and it is the substance of the rule, not a carve-out: a tool result is a
   container holding text other principals authored, and a request is prose the user
   authored whole. A fragment of the user's own sentence is still the user's.
2. **A source with no fields keeps today's rule.** An unstructured string result yields
   no leaves and falls back to whole-text matching. Field labels must not silently
   un-vouch a source whose structure the driver cannot see; that would make the rule
   fail *open* on utility and closed by accident.
3. **Vouching can only narrow.** Every field is a substring of the text, so a value
   vouched under field labels was vouched without them. The set of vouchers is monotone
   decreasing, therefore **BTU can only fall and ASR can only fall**, arm for arm. This
   is what makes the arm a gate rather than a search: it cannot buy security and utility
   at once, only trade one against the other in a known direction.

The split reuses `leaves()`, the same function the argument side is traced with, so both
sides of the match use one definition of "a value". `fields()` in `evaluation/dojo.py`
dumps AgentDojo's pydantic results to plain data and takes their leaves.

**No configuration is added or changed.** The rule carries no per-tool, per-suite or
per-argument data. `SUITES` (`sensitive` / `trusted`) and the role map (`CONTENT_ARGS` /
`TARGET_ARGS`) are byte-identical to the ones frozen before AgentDojo's first run. That
is deliberate and it is the difference between this arm and the alternative the parent
experiment refused: relabelling `get_channels` would have been a configuration tuned on
held-out results.

## Arms

`uv run python -m evaluation.dojo` with the flags below, one invocation per arm, all
four suites, no `--limit`. Each invocation also runs `allow-all`, which fixes the valid
pairs (583 expected).

| arm | flags | recorded in `README.md` |
|---|---|---|
| **A** `tekmor-args` | `--arguments` | BTU 0.55, ASR 0.07 |
| **C** `tekmor-args+endorse` | `--arguments --endorse` | BTU 0.68, ASR 0.11 |
| **A+F** | `--arguments --field-labels` | — |
| **C+F** | `--arguments --endorse --field-labels` | — |

A and C are rerun from this commit rather than quoted, so every number in the results
table below comes from one build.

The call-level arms (`tekmor`, `tekmor+endorse`) are **not** rerun and cannot move:
field labels change only `TaintTracker.origins`, which is read only when
`Policy.argument_provenance` is on.

**There is no matrix arm.** `evaluation/harness.py` drives `runtime/runner.py`, whose
tool results are unstructured strings, so every source would fall back to whole-text
matching and the run would be identical by construction. Asserting that by running it
would be theatre; it is stated here instead.

## Hypotheses

- **H1 (primary): field labels make argument-level provenance a free gain.** Arm A+F
  reaches pooled BTU > 0.45 at pooled ASR ≤ 0.04 (≤ 21/583) — the gate arm A failed
  (this is the parent experiment's H2, rerun with cause 1 fixed). **Refuted** if BTU
  ≤ 0.45 or ASR > 0.04.
- **H2: cause 1 is what field labels remove.** The 20 slack landings attributed to
  cause 1 (`injection_task_2`, `injection_task_4`) are absent from A+F, and A+F's
  remaining landings are the 21 slack URL-fetch pairs (`injection_task_3`) and nothing
  else. **Refuted** by any A+F landing outside that set.
- **H3: the utility cost is small.** BTU(A+F) ≥ 0.50, i.e. field labels give back at
  most half of arm A's ten-point gain over call level. **Refuted** if BTU(A+F) < 0.50.
  This is the hypothesis most likely to fail: it is a guess about how often a legitimate
  value is a fragment of a field rather than a field.
- **H4: monotonicity holds, as the mechanism says it must.** BTU(A+F) ≤ BTU(A),
  ASR(A+F) ≤ ASR(A), BTU(C+F) ≤ BTU(C), ASR(C+F) ≤ ASR(C). **Refuted** by any increase.
  A refutation here is a bug in the implementation, not a finding about the world, and
  would invalidate the other three.

## Predictions (stated to be checked, not to be tuned towards)

- **Arm C+F cannot pass the 0.04 gate, and the arithmetic says so before the run.**
  Arm C's landings decompose into three disjoint groups: 21 slack URL-fetch pairs
  (cause: `get_webpage` is not sensitive, in every arm), ~20 cause-1 slack pairs, 22
  workspace `injection_task_1` pairs (cause 3: `file_id` `'13'` is below `MIN_NAME`, so
  it is untraced, falls back to call level, and endorsement raises it there), and 1
  travel content-channel pair. Field labels address only the second group. So
  **ASR(C+F) ≥ (21 + 22 + 1)/583 = 0.075**, nearly double the gate. C+F is run to
  measure the decomposition, not because it can pass. Predicted: ASR(C+F) ≈ 0.075,
  BTU(C+F) slightly below 0.68.
- Read the other way, that is the useful number: if ASR(C+F) lands at ≈ 0.075, cause 1
  accounted for ≈ a third of arm C's excess ASR and **cause 3 — a value too short to
  trace, raised by endorsement — is now the dominant one**. That would say the next
  mechanism to build is the handle binding, not anything about labels.
- Most of the BTU loss is expected in **workspace and banking**, where a legitimate
  value is read out of prose (an address inside an email body, an IBAN inside a document)
  rather than out of a structured field. Slack and travel return lists and records, so
  their legitimate values are whole fields and should survive.
- The benign-utility floor: if BTU(A+F) falls to ≈ 0.45, field labels have given back
  exactly arm A's gain and the arm is worthless whatever its ASR.

## Limits (decided before the run)

- **AgentDojo is no longer held out for this change.** Cause 1 was diagnosed from
  AgentDojo results, and this arm was built to fix it. That is the exact situation the
  parent experiment's closing note warned about. It is mitigated — the rule is general,
  adds no configuration, and touches no frozen label — but it is not undone by that, and
  no number below may be reported as a held-out result. A clean test needs a benchmark
  this project has not scored against (AgentDyn, arXiv:2602.03117, is still the
  candidate). If this arm passes its gate, that run is the precondition for adopting it,
  not a nice-to-have.
- **Near-oracle provenance**, unchanged from the parent experiment and *more* load-bearing
  here: the driver replays ground truth, so values are copied verbatim and appear as
  whole fields. A model that reformats a value ("Alice Smith" → "alice smith") makes it
  untraced under field labels where substring matching might still have caught it. Field
  labels are therefore expected to cost *more* utility with a real model than this driver
  can show. The direction of that error is stated now so the result is not read as an
  upper bound on cost.
- **The field split is only as good as the driver's view of the result.** `fields()` sees
  AgentDojo's typed returns. A tool that returns one pre-formatted string is
  indistinguishable from unstructured text and keeps the old rule, so this mechanism
  rewards typed tool results and does nothing for stringly-typed ones.
- **Not addressed, by construction:** cause 2 (the content channel — AgentDojo labels
  nothing confidential, so Permitted-Flow is unarmed), cause 3 (values below `MIN_NAME`),
  the slack URL-fetch residual (`get_webpage` is not sensitive), and provenance spoofing
  by an attacker who can write into a trusted field. A field label says who *contains* a
  value, never who *authored* it, and an attacker who can create a channel authors a
  whole field.

## Amendments

(none yet)
