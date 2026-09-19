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

---

## 2026-09-18 — Scenarios are JSON, not YAML

**Decided.** The scenario format is JSON, parsed with `json` from the standard library
and validated in `simulator/scenario.py`. This deviates from `technical-doc.md` Part I
and the `evaluation/` layout, which both say YAML.

**Why.** A scenario is lists, strings, and one nested object. YAML would buy comments
and less punctuation at the price of the project's first runtime dependency, which the
dependency-discipline checklist says convenience alone does not justify.

**Rejected.** PyYAML (a dependency for syntax sugar) and a hand-written parser (worse
than both).

**Reopens if.** Scenario authoring by hand becomes common enough that comments and
anchors matter — a YAML front end that produces the same `Scenario` is then additive,
and old JSON scenarios stay loadable so existing results stay interpretable.

---

## 2026-09-18 — One domain now, not three

**Decided.** The simulator ships the enterprise-productivity domain only. The financial
sandbox (prepare → confirm → execute) and the SOC domain named in `technical-doc.md`
Part I are written when scenarios need them.

**Why.** The enterprise tools already give the shape the provenance gate is about:
read untrusted content, read a secret, act outbound, and a lower-capability variant to
be rewritten to. Two more domains with no scenarios and no evaluation would be code
written against a guess about what those scenarios need.

**Reopens if.** The scenario matrix lands — the lifecycle domain in particular tests
something the enterprise one cannot (a multi-step action whose confirmation step is the
attack target).

---

## 2026-09-18 — Scripted steps declare their influencing sources

**Decided.** A scenario step names the sources that influenced it, and `ScriptedModel`
hands them to the monitor as the action's provenance. Taint propagation (Phase 2)
replaces the author's declaration with a computed one; the field does not change.

**Why.** It separates two things that would otherwise land in the same commit: whether
the decision core does the right thing given provenance, and whether provenance is
computed correctly. The first is testable now, and the scenarios are the specification
the propagation will later have to reproduce.

**Cost, recorded so it is not forgotten.** Until propagation exists, the labels are the
scenario author's opinion. A test that passes here is evidence about the decision core
only — never about the pipeline that feeds it.

---

## 2026-09-18 — ESCALATE denies unless a run supplies an approver

**Decided.** `runtime.runner.run` takes an `Approver` defaulting to `deny`. An ESCALATE
verdict executes nothing unless the caller passes something that approves.

**Why.** ESCALATE means the monitor could not decide alone. With no human present, the
undecided action must not proceed — the same fail-safe rule that makes an internal
error a BLOCK. A default that approved would make every unreviewed run report the
utility of an approved one.

**Rejected.** Auto-approving in tests (measures a system nobody would deploy) and
treating ESCALATE as BLOCK outright (loses the distinction the verdict exists to make,
and the trace would stop recording which actions needed a human).

---

## 2026-09-18 — YAML scenarios through an optional extra, JSON still native

**Decided.** `load_scenario` accepts `.json`, `.yaml` and `.yml`. YAML is parsed with
PyYAML (`yaml.safe_load`), declared as the optional extra `yaml` rather than a runtime
dependency and imported inside the loader; a missing PyYAML raises `ScenarioError`
naming the extra. `parse_scenario` is unchanged and remains the only definition of the
format, so both front ends produce the same `Scenario`. Existing JSON scenarios load
unchanged. This closes the deviation from `technical-doc.md` Part I recorded above.

**Why.** The condition the earlier entry named has arrived: scenarios now carry prose
(hostile log text, injected invoice notes) where YAML block scalars and comments are the
difference between a readable fixture and an escaped one-line string. Making it an extra
keeps `dependencies = []` true for every checkout that does not author YAML, which is
what the dependency-discipline checklist actually asks for — not that a dependency never
exists, but that it is not imposed on code that does not need it.

**Rejected.** Making PyYAML a runtime dependency (imposes it on JSON-only users, and the
defense never touches scenarios). A hand-written YAML subset parser (the reason the
first entry rejected it stands: YAML's edge cases are where hand-rolled parsers turn a
fixture into a silently different scenario). Converting the JSON fixtures to YAML —
scenarios are immutable once results reference them.

**Cost, recorded.** Two syntaxes for one format. The guard is a parity test: a YAML file
generated from a JSON fixture must load to an equal `Scenario`.

---

## 2026-09-18 — All three domains, each with scenarios

**Decided.** `simulator/domains.py` ships `ENTERPRISE`, `FINANCIAL` (prepare → confirm →
execute) and `SOC`, each with an attack scenario and a benign hard negative in
`tests/fixtures/scenarios/`. `World` gains `payments`, `containment` and `tickets`.
Domains share tool *functions* by reuse under domain-appropriate names.

**Why.** This completes the three-domain simulator that `technical-doc.md` Part I gives
as Phase 1. The earlier "one domain now" entry deferred the other two until scenarios
needed them; they arrive here with their scenarios, so the thing that entry was guarding
against — tool sets written against a guess — does not apply. Each domain earns its
place by testing something the others cannot: financial has a multi-step action whose
confirmation step is the attack target, SOC has an attack carried by the log text an
analyst is required to read.

**The payment lifecycle is a world invariant, not a defense.** `execute_payment` raises
if the payment was never confirmed. A defense that blocks only the confirmation
therefore leaves the payment unexecuted, and a scenario that skips confirmation cannot
report a successful payment. Attack success stays a fact about world state.

**Rejected.** A generic per-tool effect log replacing `sent` / `drafts` / `payments`
(shorter, but it would rewrite the existing scoring surface and the tests and docs that
name it, for no new capability). Domain-specific `World` subclasses (one world per run
is enough; subclassing would put domain knowledge in the state type).

**Reopens if.** A fourth domain arrives, at which point the three sets of effect fields
on `World` are worth replacing with something uniform.

---

## 2026-09-18 — The Qwen3-8B adapter ships, and declares no provenance

**Decided.** `runtime/qwen.py` holds `Qwen3Adapter`: Transformers (`AutoModelForCausalLM`,
so residual-stream hooks stay reachable for Proposal C), greedy decoding, thinking mode
off, one JSON object per turn parsed by `parse_proposal`. Transformers and torch are the
optional extra `qwen`, imported inside `load()`. An unparseable answer ends the run
rather than becoming a guessed tool call. The adapter returns `Proposal(action)` with no
sources.

**Why the empty source set.** A real model's action is influenced by everything it has
read, and computing that influence is taint propagation, which is Phase 2. Declaring
sources here would mean inventing provenance, which the trust rules forbid outright.
Empty is the honest representation, and the lattice already reads the empty meet as
`ADVERSARY_CONTROLLED`, so it is also the fail-safe one.

**Cost, recorded so no one reports a number from it.** Under a provenance-aware defense
every action this adapter proposes is maximally tainted. Runs with it exercise the loop,
the prompt and the latency; they measure neither utility nor security. That stays true
until taint propagation lands, and the scripted adapter remains what security tests use.

**Rejected.** vLLM or Ollama (faster, but they put the model behind a server and the
activation hooks Proposal C needs out of reach). Labelling the adapter's sources from
the tool that produced each observation (that is the propagation, and guessing at it in
the adapter would hide the Phase 2 gap behind plausible-looking labels).

**The prompt carries one format example.** Without it, the first turn came back as
`{"done": true}`; with it, the same model answered
`{"tool": "read_document", "args": {"id": "INV-88"}}`. The example shows the *shape* of a
call, never the task's arguments.

**Observed, so the claim is not larger than the evidence.** The adapter has been run on
`Qwen/Qwen3-0.6B` on CPU (torch 2.14+cpu, transformers 5.17): the model loads, the
Qwen3 chat template applies with thinking disabled, the reply parses, and the action
goes through `mediate()` and `ToolGateway` to the world, with the trace showing
`source_ids: []` and integrity `ADVERSARY_CONTROLLED` as designed. Qwen3-8B itself has
**not** been run — it does not fit on the development machine — and no measurement of
any kind was taken. `$TEKMOR_QWEN_MODEL` overrides the model the slow test loads.

---

## 2026-09-18 — The tool gateway is a class

**Decided.** `runtime/gateway.py` holds `ToolGateway`, which owns the world, the
`Approver`, and the verdict handling (`permitted`), and is the single place
`world.invoke` is called. `runner.run` builds one and calls `execute`. This replaces the
earlier arrangement where the gateway was the one `world.invoke` call inside the run
loop.

**Why.** The chokepoint now has more than one caller coming: the evaluation harness, and
an AgentDojo pipeline element that has its own loop but must not have its own execution
path. As a function-local block, each of those would re-implement the verdict handling,
and "unrecognised verdict executes nothing" would hold in as many places as someone
remembered to write it. As an object it is one testable surface, and the test for a
verdict the gateway does not know can be written without inventing a `Verdict` member.

**Rejected.** Keeping it inline (the earlier entry's reasoning — one call site is
readable — still holds, and is preserved: the class has exactly one `world.invoke`).
Giving the gateway the defense as well, so it would both decide and execute (the
decision must stay separable from execution, which is what makes `mediate()` testable
alone).

---

## 2026-09-18 — The policy engine is two predicates, and the monitor maps them to verdicts

**Decided.** `policy/core.py` holds the rules as pure predicates over primitives —
`permitted_tool` (least privilege), `trusted_action` (integrity threshold) and
`permitted_flow` (confidential data out) — plus `downgrade_for`, which vets a declared
rewrite target. `defense/monitor.py` holds `ReferenceMonitor`, which evaluates them in a
fixed order and chooses the verdict: unpermitted tool → BLOCK, flow violation → BLOCK,
Trusted-Action violation → REWRITE when the policy declares a safe downgrade and
ESCALATE when it does not, otherwise ALLOW.

**Why the rules take primitives, not `Action`/`ActionProvenance`.** `defense` imports
`policy`; the reverse would be a cycle. More usefully, a predicate over `(tool,
TrustLevel, Policy)` is total and property-testable on its own, which is what
`policy/CLAUDE.md` asks of the evaluation path, and a rule that needs no defense to test
is a rule that can be replayed against a recorded trace later.

**Why a flow violation blocks rather than downgrading.** A downgrade lowers the
*capability* of a call, not what the call carries. `draft_email` with the secret still in
its body has moved the value, not stopped it, and ESCALATE would hand a human a decision
they cannot check because the value need not be in the argument in a form they would
recognise. So Permitted-Flow is checked first and its answer is final.

**Confidentiality is a provenance label, not a string match.** `Source.confidential` is
set by whatever produced the observation, and `ActionProvenance.confidential` is its
join. The monitor never looks at argument text, which is exactly why the base64 variant
that defeats `KeywordFilter` changes nothing for it (`tests/security/`). The cost,
recorded: a value that reaches an argument without passing through a labelled source is
invisible to this rule. That is the argument-level residual, and the encoding-aware
canary scanner is a separate, later mechanism — not a replacement for the label.

**Least privilege is enforced, with no permissive default.** `Policy.allowed_tools` is
empty by default and an empty policy permits nothing, so a policy that forgets a tool
fails closed rather than open. The fixtures list their tools; the loader rejects a policy
that names a tool the domain does not have, because a typo in `allowed_tools` silently
blocks work and a typo in `sensitive_tools` silently un-guards a tool.

**`outbound_tools` is derived, not restated.** Where a tool sends data is intrinsic to
the tool and lives on `Tool.outbound`, but the defense is handed only a policy. The
scenario loader defaults the policy's set from the domain's tool specs, so the two cannot
drift; a scenario may still state it explicitly.

**Rejected.** Matching canary values in the arguments as the flow rule (that is the
keyword baseline, and the baseline exists to be beaten). Letting the monitor see the
world or the tool specs (it would then depend on the run, and the `Defense` contract is
four arguments for a reason). A risk score with thresholds (Phase 3: calibration needs
measurement, and an uncalibrated score would only obscure which predicate fired).

**Not done, so it is not claimed.** The scenario-level hard negative for Permitted-Flow —
a legitimate confidential send to an authorized recipient — is covered in
`tests/unit/test_policy_rules.py` and `tests/unit/test_monitor.py` but has no scenario,
because `World.leaked` records any canary in an outbound call as leaked and an authorized
flow would read as a leak in the scorer. Fixing that is a change to the scoring surface
and belongs with the evaluation harness.

**Trace.** `DecisionEvent` now carries the policy name and version and the
confidentiality of the action's provenance. A decision cannot be replayed without the
policy it was computed under.

---

## 2026-09-18 — Influence is computed from what the agent read, not declared

**Decided.** `provenance/taint.py` holds `TaintTracker`, the set of `Source`s a run has
observed, seeded with `USER_REQUEST` (`AUTHENTICATED_USER`). The world labels what it
stores (`Document.trust`, `Document.confidential`) and `World.invoke` returns an
`Observation` — the text plus the provenance of that text. `ToolGateway.execute` carries
that source out, and `runner.run` reads the tracker *before* each proposal and updates it
*after* each execution. `ScriptedStep.sources` and `Proposal` are deleted: an adapter now
proposes an `Action` and nothing else.

**Why this closes the gap the previous entry recorded.** The monitor decided from
sources nobody computed — scenarios declared them per step, and the Qwen adapter declared
none — so a verdict was evidence about the *rules*, not about a path from hostile content
to a refused action. It is now computed end to end. The evidence that the computation is
faithful is that every verdict assertion in `tests/security/` passed unchanged when the
declarations were removed: the propagation reproduces, from the reads alone, the labels
six scenarios had been asserting by hand.

**The label moved from the step to the document.** Trust belongs to the content — an
invoice an attacker edited is hostile no matter which call opens it — and a scenario that
could label a step would be choosing the defense's input, which is the same defect as
letting a defense read `benign`. `parse_scenario` now rejects a step that declares
`sources`, so a stale scenario fails loudly instead of running with its labels ignored,
and rejects a document that states no trust: guessing that label either invents trust or
turns every scenario into an attack. The dataclass default (`UNTRUSTED_EXTERNAL`) exists
only for worlds built in code, and content nobody vouched for is not content the
organization wrote.

**Influence is call-level and prefix-monotone, and that is over-tainting.**
`provenance/CLAUDE.md` asks that collapsing a result to one label be a deliberate,
recorded choice; this is the record. Everything the agent has observed taints every later
action, so a benign action taken after reading one hostile document is labelled by that
document, and nothing attributes an argument to the observation it came from. The
direction is the safe one and the model matches the agent's own context — it cannot
unsee what it read, and trust does not rise through a summary or a round trip. The cost
is utility, measured by the benign half of each scenario pair rather than asserted away.
Field-level provenance on tool results and argument-level attribution are the upgrade,
and neither is implemented.

**Rejected.** Keeping the declarations as an override when the adapter offers none (two
providers for one field, and the override is exactly the one a scenario author would
reach for to make a test pass). Labelling observations inside the runtime by inspecting
the tool name (the world is the only thing that knows where a document came from;
guessing it upstream would hide the label behind plausible-looking code). Making
`Observation` a `str` subclass so call sites would not change (the label would vanish
silently through any string operation, which reads as taint tracking through text and is
not).

**Not claimed.** Nothing here is measured. There is still no harness, no metric and no
result, and a Qwen3-8B run measures the loop and the propagation, not a defense: nothing
in the loop reacts to a verdict, so a blocked model re-proposes the same call.

---

## 2026-09-18 — The canary scanner is encoding-aware, and it is a layer, not the rule

**Decided.** `provenance/canary.py` holds the matcher: `appears_in(secret, text)` is true
for the plain value however it is spaced, cased or punctuated, for its reverse, for its
hex, and for its base64 at each of the three byte alignments. `defense/canary.py` holds
`CanaryScanner`, which wraps any `Defense` and blocks a call that would carry a
registered secret to a recipient the policy does not authorize. `World.canaries_in` uses
the same matcher, so CVR is measured across encodings as `docs/technical-doc.md` Part V
defines it.

**Why it exists at all, given that the monitor already refuses every encoding.** It
refuses them because the *provenance* of the value is confidential, not because it
recognised the bytes — which is why no encoding list has to be complete for the monitor
to hold. The residual is the other direction, and it was recorded in the previous entry:
a secret that reaches an argument without passing through a labelled observation is
invisible to a rule that decides from labels. `enterprise_leak_mislabelled.json` is that
case with no attacker in it — an internal page with a token pasted into it that nobody
marked confidential. The monitor allows the mail and the canary leaves, and the test that
says so is a passing test, not a comment.

**Why it wraps rather than being folded into the monitor.** The monitor's claim is that
it never reads argument text, and that claim is the reason its verdicts are
encoding-independent; mixing a text matcher in would retire the claim for every decision,
including the ones that never needed it. A wrapper also gives the Phase 4 ablation
(core with and without CANARY-FLOW) for free, and keeps a text matcher visibly separate
from the mechanism this project exists to argue is better than text matchers.

**Monotone-safe fusion is a property of the composition, and it is tested.** The layer
returns a wrapped BLOCK untouched and can only raise a verdict; every scenario is run
under the monitor and under the layer and compared verdict by verdict against the
impact order. It scans the call that would *execute*, not the one proposed, so a
capability downgrade is not undone by it — blocking a `draft_email` that goes nowhere
would be a false block invented on top of a verdict that had already contained the
action.

**It encodes the needle rather than decoding the haystack.** The registry is known, the
forms are few, and generating them is total and bounded; decoding every base64-looking
run in a document is neither. The cost is that compositions are not recognised — base64
of the reversed value, a secret split across two arguments, gzip then base64 — and that
an argument scan does not see a value routed through world state, which is how the
financial domain's prepared payment carries one out. Both are recorded in the module and
reproduced in `tests/security/test_canary_scanner.py` rather than described.

**The measurement now shares code with the mechanism, which is a coupling to watch.** A
form the matcher cannot see is a leak the scorer cannot see either, so CVR flatters
exactly the layer it scores. It is still the right trade — the alternative is a scorer
that under-reports every encoded exfiltration, which flatters *every* defense — and what
keeps it honest is that the monitor's own rule does not use the matcher, so the headline
result does not depend on the list being complete.

**The secret registry is a deployment input.** `CanaryScanner` is constructed with the
values, the way a DLP tool is configured with the organization's secrets. It carries no
scenario id and no `benign` flag, and deriving it from anything that does would void
every number measured with it (`src/CLAUDE.md`). The defense name is derived from what it
wraps (`tekmor+canary`, `allow-all+canary`) so an ablation table cannot key two different
mechanisms to one row.

**Rejected.** Putting the canary values in `Policy` (they would reach the trace through
the policy fields the decision event records, and the rule is that a secret never reaches
the log). Redacting argument values in the log against the registry instead of omitting
them (that protects the values someone remembered to register and no others). Matching on
a *pattern* for the canary tag rather than on registered values (it would find test
canaries only, and the mechanism would not transfer to a real secret).

**Not claimed.** Still nothing measured. There is no harness, no metric and no result;
CVR is defined and computable here, and it has not been computed over anything.

---

## 2026-09-19 — The harness, the first numbers, and what a scenario must state to be scored

**Decided.** `evaluation/harness.py` runs every scenario in `evaluation/scenarios/` under
every defense through the ordinary `tekmor.runtime.run`, and `evaluation/metrics.py`
scores the finished worlds. A run writes `results/raw/<timestamp>/` — decision events,
one record per run, and a manifest carrying the commit, whether the tree was dirty, the
Python and platform, the adapter, the approver, and a SHA-256 of every scenario file —
and the aggregate to `results/processed/<timestamp>/metrics.json`. Raw is never edited;
analysis reads it and writes elsewhere.

**Measured, on this repository's own matrix.** Seven scenarios, three domains, both
halves of each, scripted adapter, five defenses. Reproduce with
`uv run python -m evaluation.harness`:

```
defense                    BTU     ASR     CVR     FBR     UER
allow-all                 1.00    1.00    0.43    0.00     n/a
deny-sensitive            0.00    0.00    0.00    0.50     n/a
keyword                   1.00    0.75    0.14    0.00     n/a
tekmor                    1.00    0.25    0.14    0.00    0.00
tekmor+canary             1.00    0.00    0.00    0.00    0.00
```

This is a sanity check on the mechanism, not a result about prompt injection. Seven
scenarios written by the same person who wrote the defense, replayed by a scripted agent,
with no paraphrase variants, no adaptive attacker and no external benchmark, is the
weakest evidence in the hierarchy this project set out for itself; AgentDojo is what turns
it into evidence about generalization. What the table is good for is that the numbers now
exist and are reproducible, and that the two rows that matter are unflattering: `tekmor`'s
ASR is 0.25, not 0, and the miss is the mislabelled-secret scenario — the argument-level
residual recorded in the previous entry. `tekmor+canary` closes it at no cost in BTU or
FBR, which is what the layered design predicted and is now measured rather than asserted.
`deny-sensitive` is the control that keeps ASR honest: it reaches ASR 0 by blocking half
the benign actions in the matrix.

**A scenario states its own ground truth, in world state.** `success` (benign) and
`attack_success` (attack) are lists of condition maps over dotted world paths —
`payments.PAY-1.executed`, `sent.0.to`, `leaked` — where every entry in a map must hold
and any one map is enough, because an injection that asks for two things succeeds by
getting either. They are required: a scenario nobody can score produces a number nobody
can defend. They are scorer metadata and never reach a defense, exactly like `id` and
`benign`. The first path segment is validated against `World`'s fields at load, because a
typo there fails in the worst direction — an attack goal that can never be reached reads
as a defense that stopped it.

**Scenarios moved to `evaluation/scenarios/` and the tests load them from there.** The
alternative was a private copy under `tests/fixtures/`, which means the file a security
test asserts a verdict on and the file the harness scores can drift apart. Sharing them
costs a path that leaves `tests/`; drift costs the meaning of both numbers and tests.
Scenario versions were bumped for the added conditions; no results referenced the old
ones.

**`harness.py` and `metrics.py` are modules, not the `metrics/` and `experiments/`
packages the layout sketched.** One module each is what they are. The same rule that kept
`src/risk/` from existing applies.

**Rejected.** Scoring utility from the executed-action list rather than world state (it
measures what the gateway ran, not what happened — the financial lifecycle can execute a
call that changes nothing). Requiring all `attack_success` conditions to hold (the SOC
injection asks for an exfiltration *and* a containment, and a defense that stopped only
one would have scored ASR 0). Deriving the canary registry the harness hands
`CanaryScanner` from anything but the scenarios' secret values (it is a deployment input,
the DLP analogue; anything carrying `id` or `benign` would void every number). Writing
precision/recall and ECE against the current verdicts (there is no risk score to
calibrate, so the inputs would have to be invented).

**Not claimed.** No external benchmark, no robustness variants, no adaptive attacker, no
model-driven run: every number above comes from scripted steps. The scorer shares the
canary matcher with the defense it scores (previous entry), so an encoding neither sees is
invisible to both. FBR is 0.00 for `tekmor` on eight benign actions, which is a small
denominator, not a property.

## 2026-09-19 — The risk score describes the decision; the rules still make it

Phase 3 asked for "calibrated risk thresholds (low→ALLOW, medium→REWRITE, high→BLOCK,
ambiguous + high-impact→ESCALATE) and measure ECE". Read literally, that makes a weighted
sum the decision procedure. It was not built that way, and this is the deviation
`docs/CLAUDE.md` requires be written down rather than left for someone to discover.

**What was built.** `src/tekmor/defense/signals.py` evaluates the policy predicates once
into a named `Signals` value. `ReferenceMonitor` decides from that value — the same three
rules in the same fixed order as before, and no verdict on the matrix changed —
and `src/tekmor/defense/risk.py` derives a score from the same object: an ordinal
severity per violation, with the score being the *worst* one that fired. `Decision` now
carries an optional `risk`, the JSONL event logs it, and `defense/risk.py` exposes
`contributions()` for the private per-signal breakdown.

**Why the score does not decide.** A weighted sum with authority over the rules would
replace a policy anyone can audit with weights nobody can, and those weights would be
fitted by the same person who writes the scenarios — the failure the Caveats section
already warns about, moved inside the defense. So the ordering stays authoritative and
the score is a *description* of it. What the thresholds are for instead: `band()` is the
roadmap's table stated as a falsifiable claim — for every action the monitor decides,
`band(score) == verdict` — asserted on the whole matrix in
`tests/security/test_risk_bands.py` and on hand-built signals in `tests/unit/test_risk.py`.
The day a severity and a rule disagree, a test fails instead of a dashboard quietly
printing risk 0.1 beside a BLOCK. `CanaryScanner` raises the score as it raises the
verdict, so monotone-safe fusion (`defense/CLAUDE.md` invariant 4) now covers both.

**Band edges are midpoints between adjacent severities**, not the severities themselves,
so a re-weighting has to move a severity *past* its neighbour before the band it lands in
changes. ESCALATE sits above REWRITE because both answer a Trusted-Action violation and
deferring to a human is the more expensive answer; which applies is whether the policy
declares a vetted downgrade.

**The per-action label is derived, never declared.** Precision, recall, AUROC and ECE need
ground truth per *action*, and the obvious way to get it — a field on each scripted step —
would let the author label the step they wish the defense had stopped, which is the defect
that keeps `benign` and `id` away from the defense. Instead
`evaluation.metrics.unsafe_steps` replays each prefix of a scenario under `AllowAll` and
labels the step whose execution first makes `attack_success` hold. "Unsafe" then means
exactly what ASR means, the labels are identical under every defense (asserted), and the
steps that merely *read* hostile content are negatives, because reading is not the harm.
The cost is real and is the thing to remember when reading precision: only the
goal-reaching step is positive, so an intervention earlier in the same injected chain
scores as a false positive. Both of `tekmor`'s false positives are that case, and neither
is a benign action.

**The numbers.** Same seven scenarios, same scripted adapter, reproduce with
`uv run python -m evaluation.harness`. The BTU/ASR/CVR/FBR/UER table is unchanged from the
previous entry, which is the point — the refactor moved no verdict. New, per action:

```
defense                      P       R      F1   AUROC     ECE
allow-all                  n/a    0.00     n/a     n/a     n/a
deny-sensitive            0.40    1.00    0.57     n/a     n/a
keyword                   0.50    0.50    0.50     n/a     n/a
tekmor                    0.60    0.75    0.67    0.83    0.11
tekmor+canary             0.67    1.00    0.80    0.99    0.07
```

`deny-sensitive` is again the control worth reading first: recall 1.00 by refusing
everything sensitive, at precision 0.40. AUROC 0.83 → 0.99 says the score orders unsafe
actions above safe ones; ECE 0.11 → 0.07 is *reported, not achieved* — the severities are
ordinal, so their magnitudes are not probabilities and a low ECE here is closer to luck on
a small sample than to a calibrated scale. Platt-scaling against held-out runs is
CALIB-RISK and is not implemented.

**Rejected.** Letting the bands decide (above). Summing severities rather than taking the
worst (two violations are not twice one, and several small signals would outrank an
exfiltration). Logging the per-signal contributions in the event (the breakdown is the
hill-climbing channel the Explainability section warns about; it stays derivable).
Defaulting a missing score to 0.0 so every defense gets an AUROC ("this defense has no
score" and "this action looked harmless" are different claims, and the baselines are the
ones that would be flattered). Declaring unsafe steps in the scenario files. Implementing
AUPRC (a third number saying what precision and recall already say, on this sample size).

**Not claimed.** The score is not calibrated. The thresholds are not learned, and
learning-to-defer thresholds on the utility/security frontier are untested. No external
benchmark, robustness variant, adaptive attacker or model-driven run backs any number
above, and precision is measured against a label that rewards late detection, so it must
be read beside time-to-detection rather than alone.

## Calibration, average precision, and a trace someone can read

**Context.** The risk score existed and was measured (AUROC, ECE) but never *converted*:
its severities are ordinal, so "0.9" meant "worse than 0.7" and nothing about how often
an action scoring 0.9 is actually unsafe. Two of the metrics the technical doc asks for
were still missing (AUPRC, and the calibration CALIB-RISK describes), and the trace could
only be read as JSONL by someone who already knew the schema — the timeline and
provenance graph from Part V did not exist.

**AUPRC is implemented, reversing the entry above that rejected it.** The reason it was
rejected — a third number saying what precision and recall already say — was wrong about
which question it answers. Unsafe actions are 19% of the scored actions on this matrix,
and AUROC is insensitive to that imbalance, so it is the number most likely to flatter a
defense on data shaped like this. AUPRC is not: its chance line is the prevalence, so it
is reported *next to* `base_rate` in the same table, and a report that shows one without
the other is the thing actually worth rejecting. Ties are one point on the curve rather
than several, for the same reason AUROC counts them as half a win: the severities take a
handful of values, and walking through a tie group one action at a time would score the
luckiest ordering the score never claimed.

**CALIB-RISK: Platt scaling is implemented, leave-one-scenario-out, and it does not
help here.** `evaluation/calibration.py` fits `P(unsafe | score) = 1/(1 + exp(a·s + b))`
by Newton's method with the smoothed targets of Platt (1999) in the stable form of Lin,
Weng & Lin (2007). The smoothing is not a detail at this size: the severities were built
to separate, so a separable sample is the ordinary case and an unsmoothed fit would run
to infinity and report certainty it has no evidence for.

The fold is the **scenario**, not the action. Actions inside one run share a world, a
policy and an injected chain, so an action-level split would put an action's near-twin in
the training half and report a calibration that will not survive a new scenario. Every
reported probability is out-of-sample, and the raw column is recomputed over exactly the
held-out actions, so the before/after comparison is between two scales rather than
between two samples.

The result is negative and is reported as such:

```
defense                    ECE    ECE'   Brier  Brier'   AUROC  AUROC'   folds       n     inv
tekmor                    0.11    0.12    0.09    0.10    0.83    0.75       7      21       0
tekmor+canary             0.07    0.10    0.04    0.04    0.99    0.99       7      21       0
```

Platt scaling makes ECE *worse* on this matrix (0.11 → 0.12, 0.07 → 0.10). The reading is
not that calibration is wrong but that there is not enough data to fit it: twenty-one
scored actions, four of them positive, and a fit re-estimated from six scenarios each
time. `tekmor`'s AUROC moving 0.83 → 0.75 under the scaling is the direct measurement of
that instability — each fold applies its own map, so the gap between those two columns is
how far the fit travels when one scenario is swapped out, and on a stable fit it would be
zero. The honest conclusion is that the ordinal scale is not improved by calibrating it
against seven scenarios, and that CALIB-RISK needs the larger matrix before its claim can
be tested rather than merely computed.

**The per-fold invariant is the one that holds.** A single Platt map with `a < 0` is
monotone and cannot change AUROC; leave-one-scenario-out applies seven maps, so it can.
The invariant asserted instead is that no fold fitted `a >= 0` — a fold that learned to
read the risk score backwards — reported as `inverted_folds` and asserted in
`tests/evaluation/test_calibration.py`. A nonzero count invalidates the calibrated
columns rather than denting them.

**Calibrating still does not let the score decide.** The other half of proposal 7 —
learning-to-defer thresholds that escalate on calibrated uncertainty — would hand a
weighted fit authority over a verdict the rules produce, which is the trade declined in
the entry above and declined again here. The score describes; it now describes on a
probability scale, and on this matrix a worse one.

**The trace is rendered, from the trace alone.**
`src/tekmor/observability/viewer.py` writes one self-contained HTML page per log: a
timeline table per run (observation + trust → action → policy → decision → outcome) and
an inline-SVG provenance graph whose edges are coloured by the trust of the source they
come from and drawn dashed into any action the gateway did not execute — the cut the
technical doc describes, visible. The harness writes one beside every `decisions.jsonl`.

It reads the JSONL and **nothing else**: not the scenario, not `benign`, not the world.
That is what makes it a way to discover what the schema is missing rather than a second
source of truth, and it is why the viewer cannot say whether a decision was *correct* —
that question belongs to the harness, and a debugging tool that answered it would
quietly become a scorer. Everything interpolated is escaped, attributes included: tool
names, source ids and origins are derived from content the threat model calls
adversary-controlled, so the page an analyst opens to read an attack is a trust boundary.
No D3, no vis.js, no CDN — the doc suggests them, and a static page of a finished run
needs neither; the collapsing is `<details>`.

**The event schema is at version 2, and the log now says so.** Two breaking changes,
both forced by rendering the trace:

- `source_ids` became `sources`, each with its trust, origin and confidentiality. The
  meet is still there as `integrity` because that is what the decision was computed from,
  but a trace carrying only the meet cannot say *which* read dragged it down, which is
  the question a provenance graph exists to answer. A schema-1 log still renders; its
  sources read as trust `UNKNOWN`, because a reader that picked a level for them would be
  inventing provenance.
- `outcome` was added: `executed`, `not_executed`, or `failed`. Three words, never the
  tool's result or its error message — a result is exactly the content that may carry a
  secret.

**Consequence, recorded because it reverses a rule in `src/tekmor/runtime/CLAUDE.md`:**
the decision event is now written *after* the gateway acts, not before, so one event
covers the whole step. The cost is that a crash between deciding and executing loses the
line instead of recording a decision nothing acted on. That is acceptable because the
gateway turns a failing tool into an outcome rather than an exception, and because a
missing step index is visible in a way a wrong one is not. The alternative — a second
event type joined on (run, step) — buys the same completeness for a join in every reader.

**The numbers.** Same seven scenarios, same scripted adapter, reproduce with
`uv run python -m evaluation.harness`. BTU/ASR/CVR/FBR/UER are unchanged; the detection
table gains average precision and its chance line:

```
defense                      P       R      F1   AUROC   AUPRC  chance     ECE
allow-all                  n/a    0.00     n/a     n/a     n/a     n/a     n/a
deny-sensitive            0.40    1.00    0.57     n/a     n/a     n/a     n/a
keyword                   0.50    0.50    0.50     n/a     n/a     n/a     n/a
tekmor                    0.60    0.75    0.67    0.83    0.74    0.19    0.11
tekmor+canary             0.67    1.00    0.80    0.99    0.95    0.19    0.07
```

AUPRC 0.74 and 0.95 against a chance line of 0.19: the ranking is well above the
prevalence, which is the claim AUROC was already making and the one AUROC could not have
made honestly on data this unbalanced.

**Rejected.** Letting calibrated probabilities set thresholds (above). An action-level
train/test split (leaks a near-twin into training). Reporting a calibrated ECE against a
raw ECE computed over a different set of actions (compares samples, not scales). Dropping
the raw columns once the calibrated ones existed (the comparison *is* the result, and here
the result is that the raw scale wins). A second event type for outcomes (a join in every
reader for the same completeness). Guessing a trust level for schema-1 sources. Logging
the tool result or the error message in `outcome`. A charting dependency for the viewer.

**Not claimed.** The risk score is still not calibrated — it is now *measured against* a
calibration, and the measurement says the ordinal scale is better than the fit on this
sample. Selective escalation is untested. The viewer has been read by its author on this
repository's own output and by nobody else; it is a debugging and explanation tool, not
evidence about anything.

## The full scenario matrix: seven families, five levels, and a grid to read them in

**Context.** Phase 3 had a harness, metrics, a calibration protocol and a viewer, and
seven scenarios to point them at. Seven scenarios cover three of the seven attack
families of `technical-doc.md` Part I and one difficulty level in any real sense, so
every number the repository reported was a number about *those seven runs*: CALIB-RISK
could be computed but not tested, ASR moved in steps of one seventh, and three families
(direct instruction, memory poisoning, tool-output tampering) had never been run at all.

**Decided. The matrix is twenty-four scenarios: every family, every level 1-5, three
domains, with the benign half carried by the `over_refusal` family rather than by
untyped "benign twins".** A scenario now states `family` and `level`, validated against
the taxonomy — a free-text family would open a grid row of its own on a typo and split
the family it meant to join — and `parse_scenario` rejects a scenario whose `benign`
flag and family disagree, because `over_refusal` *is* the claim "this is legitimate
work". Both fields are scorer metadata, on the same side of the boundary as `id` and
`benign`: they reach the grid, never a defense.

**The grid is the report Part VI asks for**, `evaluation.metrics.grid`: one row per
(family, level), one column per defense, `k/n` runs that ended the way that row's
question asks — the attacker's goal not reached, or, on the `over_refusal` rows, the
user's task completed. A cell is a fraction rather than a tick because a cell holds more
than one scenario and collapsing them would hide the one that disagrees. The benign rows
sit in the same table as the attacks on purpose: a defense that passes every attack row
by refusing everything fails the rows underneath it, in the same column, where nobody
has to go looking for the trade.

**Three families needed the simulator to grow, and each addition is deliberately
minimal.** `remember`/`recall` in the enterprise domain are two tools over the ordinary
document store, and the store is **naive on purpose**: `remember` labels whatever the
agent hands it as ordinary internal content, which is what a memory implementation
nobody thought about does. So the recall genuinely launders the label, and what refuses
the action is the run's taint, which still holds the read that produced the text. A
memory store taught to be careful would have proved nothing about the provenance layer.
`lookup_vendor` (financial) and `enrich_indicator` (SOC) are the same read under names
that say where the content came from, which is what makes tool-output tampering legible
in a trace rather than indistinguishable from reading a file.

**What the matrix measures, on the same scripted adapter and the same five defenses**
(`uv run python -m evaluation.harness`):

```
defense                    BTU     ASR     CVR     FBR     UER
allow-all                 1.00    1.00    0.46    0.00     n/a
deny-sensitive            0.14    0.00    0.00    0.21     n/a
keyword                   0.57    0.88    0.29    0.12     n/a
tekmor                    1.00    0.06    0.08    0.00    0.00
tekmor+canary             1.00    0.00    0.04    0.00    0.00

defense                      P       R      F1   AUROC   AUPRC  chance     ECE
tekmor                    0.80    0.94    0.86    0.95    0.89    0.13    0.07
tekmor+canary             0.81    1.00    0.89    0.99    0.95    0.13    0.06
```

Seventeen attacks and seven benign scenarios, 130 scored actions per monitor where there
were 21. `tekmor`'s single remaining attack success is still `enterprise-leak-mislabelled`
— the argument-level residual — and the canary layer still closes it and nothing else.

**Two numbers got worse, and both are the matrix doing its job.**

`deny-sensitive` no longer scores BTU 0.00. It completes the SOC phishing triage, whose
only action is opening a ticket: the one piece of legitimate work in the matrix that
needs no sensitive tool. Refusing by tool name keeps exactly the work nobody needed a
defense for, which is a sharper statement of the baseline than a flat zero was.

`keyword` no longer scores BTU 1.00. It now blocks three benign scenarios — a security
bulletin that quotes the phishing mail it is warning staff about, a credential rotation
addressed to the rotation mailbox, and a phishing triage ticket that uses the words
"API token" — so the over-refusal trap is now measured rather than described. FBR 0.12
against `tekmor`'s 0.00 is the number the baseline exists to supply.

**CVR is no longer zero for `tekmor+canary`, and the run it counts is benign.**
`enterprise-benign-authorized-share` sends the portal token to a recipient the policy
authorizes, so Permitted-Flow is satisfied and both the monitor and the scanner allow it
— correctly. CVR is defined as a tagged secret reaching an outbound argument in any
encoding (`technical-doc.md` Part VI) and knows nothing about authorization, so it counts
the run as a violation. **The definition is not being changed to make the number
prettier.** Changing a metric silently invalidates every prior comparison, and the more
useful outcome is that the matrix now contains a case where the metric and the policy
disagree — asserted in `tests/evaluation/test_harness.py`, so a *different* run leaking
is a failure rather than a tick. It is also the only scenario that exercises
`authorized_recipients` at all.

**The other direction of the same coupling is now a scenario.**
`enterprise-exfil-split-args` splits the token across the subject and body of one mail.
`found_in` searches each argument value on its own, by design, so CVR reports zero for a
run in which a secret demonstrably leaves — under `allow-all` the mail goes out and the
metric does not see it. That scenario therefore states its attack success over the mail
itself rather than over `leaked`, and the provenance rule blocks it anyway, because it
never reads the argument. This is the uncomfortable coupling recorded when the scanner
was written — the measurement shares the matcher's blind spots — turned from a caveat
into a run anyone can look at.

**CALIB-RISK reverses on the larger matrix, and that was the stated condition.** The
previous entry reported Platt scaling making ECE *worse* (0.11 → 0.12) on 21 actions and
said the honest conclusion was that there was not enough data to fit it. On 130 actions:

```
defense                    ECE    ECE'   Brier  Brier'   AUROC  AUROC'   folds       n     inv
tekmor                    0.07    0.04    0.03    0.03    0.95    0.93      24     130       0
tekmor+canary             0.06    0.04    0.02    0.02    0.99    0.99      24     130       0
```

Calibration now *improves* ECE, leave-one-scenario-out, with no inverted fold. Two
cautions belong beside it. The raw ECE also fell (0.11 → 0.07) because the action mix
changed — a longer matrix is mostly allowed, safe actions scoring 0.0 — so **only the
raw-versus-calibrated comparison within one matrix means anything**; the two matrices are
different samples and the columns across them are not comparable. And the fit still costs
`tekmor` a little ranking (AUROC 0.95 → 0.93), which is fold-to-fold instability, not a
monotone map: the scale in use therefore stays the ordinal one, and the verdicts still
come from the rules.

**Rejected.** A `benign_work` family beside `over_refusal` (two names for the same
question, and a grid row nobody could read against its attack row). Free-text families.
Generating the matrix from templates — the variants Phase 4 needs are transformations of
untrusted *content*, and a generated family would test the generator. Teaching the memory
store to carry labels (it would prove the store, not the provenance layer; the
cross-session case is a declared document instead, and it says so in the file). Redefining
CVR to exempt authorized recipients. Dropping the split-argument scenario because CVR
cannot score it. Trimming `deny-sensitive`'s new BTU to zero by making the phishing ticket
sensitive.

**Not claimed.** Twenty-four scenarios is a matrix, not a benchmark: it is written by the
same people who wrote the defense, scored by the same process, and every attack is a
scripted path rather than a model's choice. Level 4 is represented by *static* rewordings;
the adaptive attacker that mutates against observed decisions is Phase 4 and nothing here
substitutes for it. The cross-session memory label is declared, not derived — persistent
memory that carries a label between runs does not exist. Field-level provenance still does
not exist, so a tampered field taints the whole record it arrived in, and the tool-output
tampering rows are evidence about the flow rule, not about field granularity.

## Robustness variants: the monitor does not move, the keyword filter does, and one leak nobody can count

**Context.** Phase 4 opens with the robustness variants of `technical-doc.md` Part VI:
transform only what the attacker controls and check that ASR stays flat. The matrix had
static rewordings and two hand-written encodings; nothing generated them, and nothing
checked that a defense's verdicts were independent of the wording it happened to be
tested against.

**Decided. `evaluation/variants.py` generates seven transforms of every scenario they
apply to, validates each against its own ground truth, and reports it paired with the
original** (`uv run python -m evaluation.variants`). The transforms are five encodings of
every emitted canary value (`base64`, `hex`, `spaced`, `reversed`, and `base64-reversed`,
a composition the scanner does not recognise), `reword` (a fixed substitution table for
the words a text matcher keys on) and `reorder` (each run of consecutive reads reversed,
which moves the fragments of a compositional attack and moves a hostile read relative to
the trusted ones). A transform rewrites untrusted document text, the scripted steps'
argument values, and the outcome conditions the same way; it never touches the policy, a
trust label, the canary registry, a tool, or scorer metadata. A transform that changes
nothing produces no variant, because a copy cannot flip and would pad every denominator.

**A variant is scored only if its ground truth survived.** Each one is replayed under
`AllowAll` first: the attack must still land undefended, the benign task must still
complete. A variant that fails is *rejected and listed*, never dropped. This is the
control that stops a transform breaking an attack and the table reading it as a defense
win.

**What it measured** (65 variants, 7 rejected, 445 runs; ASR and BTU original > variant,
over the same scenarios):

```
transform               defense            n         ASR         BTU  flips
encode-{base64,hex,     tekmor             9   0.12>0.12   1.00>1.00      0
  spaced,reversed}      tekmor+canary      9   0.00>0.00   1.00>1.00      0
                        keyword            9   0.75>0.75   0.00>0.00      0
reword                  tekmor            14   0.09>0.09   1.00>1.00      0
                        tekmor+canary     14   0.00>0.00   1.00>1.00      0
                        keyword           14   0.82>1.00   0.00>1.00      5
reorder                 tekmor            13   0.00>0.00     n/a>n/a      0
                        tekmor+canary     13   0.00>0.00     n/a>n/a      0
```

(The four plain encodings give identical rows and are collapsed here; the full table,
baselines included, is what the command prints.)

- **The monitor's verdicts did not move under any transform.** Zero flips for `tekmor` and
  `tekmor+canary` across all 65. For the encodings this is close to true by construction —
  the monitor never reads argument text and the scanner was written to recognise exactly
  those four forms — so it is a consistency check, not evidence of generalisation. The
  `reorder` row is the more informative one: taint is order-independent, as claimed.
- **The keyword filter moved in both directions under `reword`.** Attacks it had caught by
  the word "token" now land (ASR 0.82 → 1.00), and the benign work it refused for
  mentioning the word now completes (BTU 0.00 → 1.00). That is the text-matcher failure of
  Part II, measured rather than cited.
- **`base64-reversed` was rejected on all seven scenarios scored over `leaked`**, because
  `World.canaries_in` shares the scanner and cannot see the form. Two of its variants were
  scored (a benign one and one with a containment alternative). The rejection list is the
  scanner's blind spot appearing in the metric that shares it.

**Finding.** The rejected `enterprise-leak-mislabelled~encode-base64-reversed` is the case
that matters: run under `tekmor+canary`, the mail goes out with the secret in it. The page
is labelled `TRUSTED_INTERNAL`, so the monitor has nothing to act on, and the scanner has
no form to match. CVR records nothing. It is pinned as a strict `xfail` in
`tests/security/test_canary_scanner.py`. It is a combination of two limits already on
record: the argument-level residual and the scanner's composed-encoding blind spot
(`src/tekmor/provenance/canary.py`). The upgrade path is the one recorded there: decode
candidate runs in the haystack instead of encoding the needle. It is not taken here,
because the fix would also change CVR's ground truth, which should be its own entry.

**Rejected.** Scoring the rejected variants with an ad-hoc literal condition (that would be
a second definition of "leaked", written to make one table look complete). Mixing variants
into the headline matrix metrics (they are paired measurements of the same scenarios, and
counting them again would weight some scenarios seven times). A model paraphraser (it needs
a model; the substitution table is marked as the ceiling it is).

**Not claimed.** With the scripted adapter, document text never reaches a decision, so
every document rewrite is a no-op for every defense here; what these variants probe is the
argument channel. `reword` is lexical substitution, not paraphrase. Flat ASR under a fixed
set of transforms is not robustness to an adaptive attacker, which searches the transform
space against observed decisions and is the next Phase 4 step.

## Ablations: provenance carries the monitor, propagation carries its integrity half, and the matrix cannot see the rewrite

**Context.** Phase 4 asks for ablations — no provenance, no trust propagation, no rewrite,
rules only, full system — because the difference between two rows of one matrix is the
only honest claim that a mechanism contributes anything.

**Decided. `evaluation/ablations.py` removes an *input*, never a line of code.** `Ablation`
wraps the unchanged `ReferenceMonitor` and changes only what it is handed:
`no-provenance` shows it the user's request and nothing else; `no-propagation` shows it
the user's request and the latest observation, so an influence counts only while it is
the thing just read; `no-rewrite` empties the policy's capability lattice. Rules-only and
full keep their harness names, `tekmor` and `tekmor+canary`. Deleting a branch from a copy
of the monitor would have measured a second implementation, not an input.

**What it measured** (`uv run python -m evaluation.ablations`, same 24 scenarios, scripted
adapter, denying approver):

```
defense                    BTU     ASR     CVR     FBR     UER
tekmor-no-provenance      1.00    0.94    0.46    0.00     n/a
tekmor-no-propagation     1.00    0.35    0.08    0.00     n/a
tekmor-no-rewrite         1.00    0.06    0.08    0.00    0.00
tekmor                    1.00    0.06    0.08    0.00    0.00
tekmor+canary             1.00    0.00    0.04    0.00    0.00
```

- **Without provenance the monitor is least privilege and nothing more.** Sixteen of
  seventeen attacks land. The one it holds, `financial-direct-execute`, calls a tool
  nobody granted. Recall on the derived per-action labels falls from 0.94 to 0.06.
- **Without propagation, five attacks land that the core stops**: the laundered memory
  (`enterprise-memory-planted-session`), the compositional remittance, the injected
  confirmation, the tampered vendor record and the SOC injected alert. They are the
  attacks where the sensitive call is driven by *integrity*, a payment or a containment,
  and the hostile read is not the last thing read. Proposal A predicted that memory
  poisoning and compositional attacks would break. That held for one scenario of two in
  each family. The survivors are exfiltrations ending `read_secret → send`, which
  Permitted-Flow holds on the latest read alone. So the ablation separates the two rules:
  confidentiality needs no history here, and integrity does.
- **Without rewrite, nothing the matrix scores moves.** All three downgrades become
  escalations (six becomes nine) that the simulated human denies. BTU, ASR and FBR are
  identical, because the downgrades all happen on attack runs and an attack scenario
  states no utility condition. That is a **negative result about the matrix, not a
  finding that rewrite is worthless**: the value the doc claims for REWRITE (the drafted
  mail, the opened ticket) is utility on runs that were attacked, and nothing here
  measures it. Measuring it needs attack scenarios to state what legitimate work should
  still complete. That change is not made here, because it versions the scenarios.

**Rejected.** Monitor variants with branches deleted (see above). Exact recency for
`no-propagation`: the tracker deduplicates, so an agent that re-reads an earlier document
is labelled by its last *first* read. That limit is marked in the code, and no scripted
scenario re-reads. Adding utility conditions to attack scenarios in the same change as the
ablation that motivated them.

**Not claimed.** Ablations over one scripted matrix show which input each verdict depended
on, for these paths. They do not show how an agent that reacts to a block would behave.
