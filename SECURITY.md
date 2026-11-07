# Security policy

Sextant builds transactions that move funds, so please report problems
privately before talking about them in public.

## Reporting

Use GitHub's private vulnerability reporting on this repository ("Security" →
"Report a vulnerability"). If that is unavailable, contact the owner through
their GitHub profile (`labrinyang`). Do not open a public issue for a
suspected vulnerability.

Please include what you did, what happened, and what you expected; a
reproduction against a pinned block helps. We will acknowledge a report as
soon as we can and tell you what we find. We do not run a paid bounty.

## Scope

- The solver: `crates/` and `src/`. Quotes are computations; the process
  holds no keys and signs nothing.
- What is not in scope: the 0x Settler, AllowanceHolder, pool contracts and
  RPC providers Sextant calls, and deployments an operator misconfigures
  (for example exposing `/quote` publicly, which this repository warns
  against).
