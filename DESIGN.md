# DESIGN.md — sigma-verdict

## Problem
Detect Sigma-style selections (`EventID: 4728` plus
`CommandLine|contains: 'whoami'`) deterministically on-host, without
regex backtracking (ReDoS) and without silent data loss (truncation,
defaulted fields, ignored modifiers).

## Shape
```
YAML text --[boundary, SPARK off]--> Compiled_Rule --[core, SPARK Silver]--> Eval_Result
```
- `src/`: generic SPARK core (`Sigma_Verdict.Engine`). Capacities are
  generic formals; `Sigma_Verdict.Limits` holds reviewed defaults.
  `proof/` analyzes this directory only.
- `boundary/`: adayaml event-driver (`Sigma_Verdict.Boundary`,
  `SPARK_Mode (Off)`). Translates YAML into core values; every lossy
  situation becomes an explicit `Load_Error`, never truncated data.
- `tests/`: `smoke` (core) + `yaml_smoke` (end-to-end) + corpus.

## Key decisions
- Bounded strings everywhere; overflow is `Too_Long`/`Too_Many_*`,
  never truncation (norm from `pcapng-in-ada`, `shacl-ada`).
- `contains`/`startswith`/`endswith`: linear scan, ASCII
  case-insensitive fold. No `GNAT.Regpat` (backtracking ReDoS,
  AdaCore Gem #25).
- Full `Modifier_Kind` enumeration designed in from day one
  (`https://sigmahq.io/docs/basics/modifiers.html`); Phase 1a evaluates
  bare/`contains`/`startswith`/`endswith` plus the structural flags
  (`cased`, `all`, `exists`). Chains with several matchers fail closed
  (no silent shadowing); `exists` loads only standalone with a boolean
  value (`Load_Bad_Value` otherwise). Everything else (`re`,
  wildcards, `windash`, `wide`, `base64*`, `cidr`, comparisons,
  `fieldref`, `expand`, `near`, `aggregation`) answers
  `Error_Unsupported_*` — fail-closed, never silently ignored.
- Condition tree (`Compiled_Rule.Nodes`) answers `1 of`/`all of`;
  `near`/`count` reserved as explicit errors.
- Recursion in `Eval_Node` carries fuel (`Max_Condition_Nodes`) so a
  cyclic node graph fails closed instead of overflowing the stack.
- No `use` clauses across package boundaries in spec files; explicit
  qualification keeps SPARK flow analysis cheap.

## Non-goals (Phase 1)
`re`/wildcard matching (needs Thompson NFA Pike VM, like
`shacl-ada`'s `sh:pattern`), `near`/`aggregation`, multi-document
streams, non-UTF-8 input handling beyond adayaml.
