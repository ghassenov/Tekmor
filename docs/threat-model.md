# Threat model

Who the adversary is, what they can do, and what Tekmor does and does not try to stop.

---

## The setting

A tool-using LLM agent acts on behalf of an authenticated user. It can read from sources
the user does not control — inbound email, web pages, documents, third-party API results,
its own long-term memory — and it can call tools that change the world: send money, send
mail, share files, delete records.

The gap Tekmor addresses is that these two capabilities meet inside one context window.
Text that was merely *read* can end up *instructing*. This is indirect prompt injection,
and it is a confused-deputy problem: the agent holds the user's authority and is tricked
into spending it on someone else's goal.

## The adversary

**Assumed capabilities.** The attacker can:

- place arbitrary text where the agent will read it — a web page, an email body, an
  invoice, a calendar invite, a file comment, a Slack message;
- see the defense's *public* outputs: whether a call succeeded, and the coarse reason
  codes attached to a refusal;
- adapt. Attacks are not one-shot. The attacker may rephrase, encode (base64, hex,
  spaced, reversed), split a payload across steps, or reorder what the agent reads, and
  may iterate against observed outcomes.

**Assumed limits.** The attacker cannot:

- modify Tekmor's code, policy, thresholds or trust labels — these carry `SYSTEM_POLICY`
  trust and are not writable by observed content;
- forge the authenticated user's identity;
- read the private half of the trace (per-signal risk contributions, judge
  probabilities). These are withheld precisely because they are a hill-climbing channel.

The adaptive assumption is load-bearing. A defense evaluated only against a fixed attack
set reports an upper bound on its own security. The published literature is blunt about
this: adaptive attacks reach >50% success against eight defenses in one study and >90%
against all twelve in another. Tekmor is therefore built so that its guarantee does not
rest on recognising attack text, and is tested with an attacker that hill-climbs against
its observable outputs.

## Attack families

The scenario matrix covers seven families at five difficulty levels. They are not
academic categories; each one breaks a different assumption.

| Family | What it does |
|---|---|
| `direct_instruction` | The user's own request is the attack — asking for a credential outright. |
| `indirect_injection` | Hostile instructions arrive inside content the agent reads. |
| `exfiltration` | A secret is routed outward, often encoded to defeat text matching. |
| `tool_output_tampering` | A tool returns data an attacker controls — a corrupted vendor record, poisoned threat intel. |
| `memory_poisoning` | Hostile content is planted in long-term memory and recalled later, when its origin is easy to forget. |
| `compositional` | No single step looks dangerous; the attack exists only in the sequence. |
| `over_refusal` | **Benign work that looks alarming.** A false block is a failure too. |

That last row is not filler. A security layer that blocks legitimate work is a security
layer that gets disabled, so false-block rate is a headline metric and roughly a third of
the matrix is benign hard negatives. Over-tainting is a real failure mode, not a safe
default.

Difficulty levels 1–5 scale from an unobfuscated single-step attack to multi-step,
reworded, encoded and long-horizon variants.

## What Tekmor is designed to stop

**Untrusted content driving a consequential action.** This is the core guarantee and it
is structural: a sensitive tool call whose influences fall below the integrity threshold
is refused or downgraded regardless of what the text says, how it is worded, or whether
anyone has seen that attack before.

**Secrets leaving through an argument.** The canary layer scans outbound arguments across
encodings, so exfiltration is defined and measured across the encodings an attacker would
actually use.

**Blast radius.** Where an action cannot be permitted as proposed, the capability
downgrade keeps the task moving while removing the irreversible effect.

## What it does not stop

Stated plainly, because a defense whose limits are vague is a defense nobody can rely on.

- **A value laundered through world state.** The canary scanner reads arguments. A secret
  bound into the world at an unguarded step and later referenced by an opaque handle
  (`PAY-1`, `file_id: '13'`) is outside it. The same blind spot appears in argument-level
  provenance, and it is currently the largest known residual.
- **Reads that are themselves the goal.** If fetching an attacker-chosen URL *is* the
  attack, and the deployment does not classify that read as sensitive, the rules do not
  fire. This accounts for 21 of the landings on AgentDojo and is a property of the frozen
  configuration, deliberately not tuned away.
- **Composed encodings past the canary layer.** One case — base64 of a reversed token —
  leaks a mislabelled secret past the scanner. It is pinned as a failing test rather than
  quietly removed.
- **A wrong deployment configuration.** Tekmor is told which tools are sensitive and which
  sources are trusted. Those labels are deployment input. A tool mislabelled trusted is a
  hole, and under argument-level granularity there is no "meet" over all reads to mask it.
- **Anything about model-driven agents.** Every AgentDojo number in this repository was
  produced by a driver that replays ground truth and obeys every injection. See
  [limitations.md](limitations.md); this one qualifies nearly everything else.

## Where the trust boundary sits

Tekmor mediates at the **tool boundary**, not at the text boundary. It does not ask "is
this text malicious?" It asks "given everything that influenced this call, is this call
permitted?"

The consequence is that the agent can freely read low-integrity content — summarise a
hostile email, triage a phishing report, read an invoice from an unknown vendor — as long
as that content does not become the authority for a consequential act. "Untrusted" must
not collapse into "unusable", or the agent stops being useful.
