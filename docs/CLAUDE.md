# CLAUDE.md — docs/

Scope: project documentation. Root rules still apply.

- **`technical-doc.md` is authoritative** project documentation unless explicitly
  superseded by a later document that says so. Treat it as the source of truth for the
  threat model, architecture, trust lattice, metric definitions, and roadmap.
- Architectural changes must be documented here in the same PR that makes them. If an
  implementation intentionally deviates from `technical-doc.md`, state the deviation and
  the reason rather than quietly letting the document go stale.
- **Do not fabricate references.** Every citation needs a real, checkable source
  (arXiv ID, venue, repository). Preserve the origin of any borrowed claim or number, and
  attribute reported numbers to the paper that reported them.
- Distinguish **established facts** (measured and published, with a citation),
  **our own measurements** (with the run that produced them), and **hypotheses**
  (unverified). Never present a hypothesis or an expected result as an observation.
- Numbers from external papers are measured on *their* benchmarks against *their* attack
  sets. Treat them as upper bounds and say so where it matters.
- Keep documentation synchronized with the implementation. If a document describes
  something that is not built yet, mark it planned.
- **`decisions.md` is append-only.** Record a decision when it closes off an alternative
  someone would otherwise reasonably retry: what was decided, why, what was rejected, and
  what would reopen it. Do not edit or delete past entries — a reversal is a new entry
  that references the old one. Routine implementation choices do not belong there.
- Prefer updating an existing document over adding a near-duplicate one.
