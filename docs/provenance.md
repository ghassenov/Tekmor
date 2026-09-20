# Provenance and trust

How Tekmor knows where an action's influences came from, and what it does with that.

---

## The lattice

Six trust levels, totally ordered:

```
SYSTEM_POLICY          the deployment's own rules. Never writable by observed content.
   >  AUTHENTICATED_USER    the user's own request.
   >  TRUSTED_INTERNAL      the user's own data, or their institution's.
   >  UNTRUSTED_INTERNAL    internal but not authored by the user or the institution.
   >  UNTRUSTED_EXTERNAL    anything from outside. The default for unknown sources.
   >  ADVERSARY_CONTROLLED  known-hostile.
```

![Trust lattice, and integrity as the meet](../assets/trust-lattice.svg)

Two properties matter more than the exact rungs:

**Unknown is not trusted.** A source nobody labelled is `UNTRUSTED_EXTERNAL`, never
trusted. If provenance is uncertain, that uncertainty is represented explicitly. Trust is
never invented to fill a gap.

**Integrity is the meet.** An action's integrity is the *lowest* trust level among
everything that influenced it. One hostile read drags the whole action down. This is
Biba-style integrity: information does not become more trustworthy by being combined with
something better.

Separately, sources carry a **confidentiality** label, which drives the Permitted-Flow
rule — whether data of a given sensitivity may leave by a given route.

## How influence is computed

Early versions had scenarios *declare* which sources influenced a step. That was replaced,
because a hand-written label proves nothing about the pipeline.

Now influence is **computed from what the agent actually read**. The world labels stored
content; a tool call returns that label with its result; `TaintTracker` accumulates labels
over the run. Nothing declares its own provenance, so a verdict is evidence about the
whole path rather than about an annotation somebody wrote.

The default granularity is **call-level and prefix-monotone**: every observation the agent
has seen taints every later action. This is the conservative direction, and its cost is
real — a benign action taken after reading one hostile document is labelled by that
document. The benign half of every scenario pair exists to measure exactly that cost.

## Endorsement

Pure taint propagation over-taints. On AgentDojo, call-level taint drove benign utility
down to the `deny-sensitive` baseline on three suites of four — that is, the defense
became as useless as blocking everything.

**Endorsement** is the FIDES-style escape hatch: when the user's own request names a
resource, content from that resource is raised in integrity, because the user vouched
for it. Opt-in per policy (`Policy.endorse_named`).

It buys utility and it costs security, and both are measured: on AgentDojo, pooled BTU
0.45 → 0.69 and ASR 0.04 → 0.15. That is a trade, not a free win, and it is recorded as
one.

The mechanism has a known weakness, marked in the code: an attacker who can create a
resource whose *name* is a phrase in the user's request borrows the endorsement.
Structured endorsement — where the user attaches the resource rather than naming it —
is the upgrade, and it needs an interface that does not exist yet.

## Finer granularity: built, measured, off

Two refinements exist behind policy switches and are **disabled by default**. Both are
worth understanding, because the reasons they are off are more interesting than the
switches.

### Argument-level provenance (`Policy.argument_provenance`)

Instead of asking "did untrusted content influence this call?", ask "did untrusted
content determine *this authority-bearing argument*?" Content arguments (a mail body, a
subject) are exempt as payload; target arguments (recipients, URLs, accounts) are never
raised by an endorsement unless the policy explicitly says so.

Measured on AgentDojo, it buys utility (BTU 0.45 → 0.55) and costs security
(ASR 0.04 → 0.07). The pre-registered gate asked for dominance on both axes; a trade
fails it.

More importantly, it introduces a dependency the call-level rule did not have:

> Under argument granularity, **every `trusted` label must be right**, because there is
> no meet over all reads to hide a wrong one.

Call-level taint takes the minimum over everything read, so any untrusted read masks a
mislabelled source. Argument-level tracing removes that mask. That is a worse failure
mode than over-tainting, and it is why the switch is off.

### Field-level labels (`TaintTracker.field_labels`)

The follow-up, and a genuinely clean diagnosis. The rule is:

> A tool result vouches for a value it **returned**, never for a *fragment* of one.

The earlier conclusion — "every trusted label must be right" — turned out to be half
wrong. On AgentDojo, `get_channels` *is* trusted for the channel list it returns. The
injection was a whole channel name, and the attacker's URL was a **fragment** of it. The
defect was granularity, not labelling, and it is fixable without touching a single label.

Field labels removed every one of those landings (slack ASR 0.39 → 0.20 in the affected
arm) at zero measured benign cost.

They are still off, and the binding reason is methodological rather than numerical:
**the failure was diagnosed on AgentDojo and the fix was built for it, so AgentDojo is no
longer held out for this change.** A mechanism that fixes a fault found in a benchmark
cannot be adopted on that benchmark's own numbers. Adoption is gated on a benchmark this
project has not yet scored against.

The zero cost is also not a deployment estimate, and the pre-registration said so before
the run: the driver replays ground truth, so benign values are copied *verbatim* out of
structured results — precisely the case where a value is a whole field. A model that
reformats a value makes it untraced, which falls back to call level: safe, and costly in
utility. That cost is real and this harness cannot measure it.

## The largest remaining gap

Cross-step binding for handles.

An authority value can be laundered through world state: bind it at a step the policy does
not consider sensitive, then act on an opaque handle. `prepare_payment` fixes the payee;
`confirm_payment` and `execute_payment` carry only `PAY-1`, which is too short to trace
and falls back to call level. Argument-level provenance as implemented sees only the
arguments of the call in front of it.

This is the same shape as the canary scanner's recorded blind spot, and after field labels
it is the **largest** residual group — 22 pairs against the 20 that field labels fixed.

Short opaque identifiers are a systematic hole rather than an edge case: `file_id: '13'`
is untraceable by length, and the minimum-length floor that prevents a two-character value
from matching anywhere is doing more work than intended.
