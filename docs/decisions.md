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
