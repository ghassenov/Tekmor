# CLAUDE.md — src/tekmor/provenance/

Scope: trust labelling and taint propagation. Root and `src/` rules apply.

## Status

**Implemented:** `trust.py` (the lattice, its meet, and `Source` with its integrity and
confidentiality labels), `taint.py` (`TaintTracker`: the influences accumulated over one
run, seeded with the request that asked for the work), `canary.py` (the
encoding-aware secret matcher: plain, separator-broken, case-shifted, reversed, hex, and
base64 at each of the three byte alignments).

**Not implemented:** field-level provenance, and the endorsement primitive.

**The deliberate coarseness, recorded as the rules below require.** Influence is
call-level and prefix-monotone: an observation the agent has seen taints every action it
proposes afterwards, so a benign action taken after reading one hostile document carries
that document's label. The world labels whole observations rather than fields, and no
argument is attributed to the observation it was copied from. This is the conservative
direction, it is over-tainting, and the benign half of each scenario pair in
`tests/security/` is what measures the cost. See `docs/decisions.md`.

## Trust lattice

```
SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL >
UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED
```

These are integrity labels (Biba): information may not flow up in integrity. An action's
integrity is the **minimum** integrity over all inputs that influenced it. Confidentiality
labels (secrets, canaries) are tracked separately from integrity.

## Rules

- **Preserve provenance end to end.** Source, origin, trust level, tool identity, user
  identity, execution context, timestamp, and transformation history travel with the data.
  Never drop a field because a downstream stage does not currently read it.
- **Unknown provenance is represented explicitly and treated as low integrity.** Never
  invent trust, and never default missing provenance to a trusted value.
- **Trust is inherited.** A memory entry written after reading untrusted content stays
  untrusted when recalled. Trust never increases through summarization, paraphrase,
  serialization, or a round trip through memory.
- **Provenance is field-level, not call-level.** A single tool result can mix trust
  levels across fields; preserve that granularity. Collapsing a result to one label is
  the documented "argument-level residual" gap, so it must be a deliberate, recorded
  choice.
- **Raising trust requires an explicit endorsement primitive** with its own trace event,
  never an implicit side effect.
- **Over-tainting is a real failure.** Label creep collapses utility. If a change widens
  taint, check the effect on benign hard negatives.
- Label operations (join, meet, comparison) belong here and must be pure and total, so
  the lattice can be property-tested independently of the defense.
