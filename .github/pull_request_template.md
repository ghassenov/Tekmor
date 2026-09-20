## What changed

<!-- The change, in a few sentences. -->

## Why

<!-- Motivation, and the issue this closes if any. -->

## How it was implemented

<!-- Approach and any notable design decisions. If this deviates from
     docs/10-research-report.md, say so and why. -->

## Tests performed

<!-- What was actually run, and the result. Do not claim a test that was not run. -->

- [ ] `uv run pytest`
- [ ] `uv run ruff check .`

## Research implications

<!-- Hypotheses affected, results, ablations. Label claims: implemented / tested /
     observed / hypothesized / planned / inferred. N/A if none. -->

## Security implications

<!-- Does this touch the decision core, provenance, policy, or trust propagation?
     Which invariants are affected? Which adversarial tests cover it, including
     benign hard negatives? N/A if none. -->

## Observability / evaluation implications

<!-- Trace schema changes, new events or fields, metric definition changes, effects on
     reproducibility of existing results. N/A if none. -->

## Known limitations

<!-- What this does not handle. Be honest; a documented gap is worth more than a
     silent one. -->

## Follow-up work

<!-- What comes next, and any issues opened. -->

## Checklist

- [ ] Branch follows the naming convention; no direct commits to `main`
- [ ] Conventional Commit messages, logically focused
- [ ] No secrets, credentials, or canary values added or logged
- [ ] Documentation updated if the architecture changed
- [ ] No fabricated results, citations, or measurements
