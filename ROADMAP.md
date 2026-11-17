# ROADMAP.md — sigma-verdict: run any current Sigma 2.x rule

Goal: `sigma-verdict` evaluates any current Sigma 2.x detection rule —
full detection semantics in the SPARK core, fail-closed on everything
outside the proven subset, silver-clean at every step.

Locked decisions (2026-11-16):
- D1 Correlation state is caller-owned. The library stays stateless and
  reentrant; multi-event rules take an explicit bounded state record
  in/out (norm for SPARK detection-library workflows).
- D2 IPv6 CIDR is in scope (P2). 128-bit parse + prefix match in core,
  malformed input fails closed.
- D3 `near` stays explicitly `Unsupported`. Deferred, not opposed: the
  `N_Near` node reserves the shape so it can be added later without an
  API break. Effort stays on supported goals.
- D4 Conformance corpus is hand-written vectors only. SigmaHQ's rule
  corpus is DRL-licensed and is never vendored; pySigma is a grammar
  reference, not a test source.

## P0 — Close-out + scaffolding (prerequisite for all below)
- Close the open silver findings (type invariants, bound asserts).
- `prove-silver` fully green, not just tracking.
- Exit: silver level 2 `--checks-as-errors=on` clean on `dev`.

## P1a — Structural modifiers (first build)
`cased` (opt-out of ASCII folding), `all` (list conjunction),
`exists` (standalone boolean presence), plus the chain legality gate:
at most one matcher token per chain, illegal combos fail closed as
`Unsupported` (no silent shadowing). No new buffers, no new proof
machinery. `exists` is standalone with a boolean value at load.

## P1b — Value views
`windash` (placeholder-exact per the pySigma reference: only ASCII
`-`/`/` at non-word-boundary positions expand, 5-way, variable stride
in the matcher — canonical folding would over-match, so no
canonicalization), `wide`/`utf16le`/`utf16be` (NUL-interleaved views,
ASCII-only needles, rejected at load otherwise),
`utf16` (BOM variant), `base64` (encoded form only, never the plain
value), `base64offset` (exact 3-phase construction per pySigma: prepend
0/1/2 spaces, encode, cut per offset). As built: derivation lives in
the boundary (auditable, SPARK off); the core matches over derived
bytes plus stride-aware windash matchers. `base64offset` requires a
single value (lists refused with `Load_Unsupported_Chain`);
`wide`-family and `base64`-family never mix in one chain
(`Unsupported`); `utf16le` is not a canonical token (rejected).

## P2 — Comparisons + CIDR (v4 + v6)
`gt`/`gte`/`lt`/`lte` on the `E_Int` path; 32-bit and 128-bit prefix
matching; malformed input fails closed. Boundary rejects non-numeric
comparison values with `Load_Bad_Integer`. As built: IP parse/match
lives in the standalone `Sigma_Verdict.IP` seam unit (core
constructors + matching, boundary maps failures to `Load_Bad_Value`);
host bits mask leniently (formal spec silent, documented divergence
from pySigma strictness); `::`-compression, embedded IPv4 and bare-IP
full prefixes supported; v4 sides compare in IPv6 space as
`::ffff:0:0/96`. `neq` stays out of scope.

## P3 — Wildcards + `re` subset (largest proof cost)
Unescaped `*`/`?` in a plain value already means wildcard in Sigma, so
the boundary detects implicit wildcards and routes them to the pattern
path — required for "any rule", not just explicit modifiers. Glob
`*`/`?` compile to NFA; `re` subset (literals, `. * + ?`, classes,
`^$`, `i`/`m`/`s`) runs on a Thompson NFA Pike VM with explicit step
fuel (norm: `shacl-ada` `sh:pattern`). No `GNAT.Regpat` anywhere
(backtracking ReDoS, AdaCore Gem #25). `fieldref` + `expand` compose
here.

## P4 — Condition grammar
Parentheses, `NOT` binding, `1 of them` / `all of them`, generalized
`1 of` / `all of`, aggregation `count() by` and bare `count()` (wires
up reserved `N_Count`; multi-event counting feeds the P5 state model).
`near` stays explicitly `Unsupported` per D3.

## P5 — Correlations
`event_count`, `value_count`, `temporal`, `temporal_ordered` on the
D1 state model: new generic with caller-owned bounded ring-buffer
window (capacities as generics); `timeframe` parsed in boundary, core
counts ticks. Stateless `Evaluate` is untouched.

## P6 — Validation hardening + corpus
Loader-side schema checks (required `title`/`logsource`/`detection`,
condition reference resolution, chain legality such as
`windash`-on-strings-only, `id`/`status`/`license` shape) as new
`Load_Error` variants with byte-offset `Detail`. Hand-written vector
per modifier/condition per D4.

## Invariants (every phase)
- SPECIFICATION.md delta + CHANGELOG.md entry on any public API change.
- `verify.sh` (build + tests + flow proof) green.
- Silver level 2 `--checks-as-errors=on` clean before merge.
- Tests-first for each evaluator; fail-closed, no truncation, no
  backtracking matchers.

## Non-goals (carried over)
Multi-document YAML streams, query backends (this crate evaluates; it
does not translate to SIEM queries), `near` semantics (D3),
graduating `Sigma_Verdict.IP` to a standalone Alire crate (explicit
future, shaped for by the seam).
