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
  (`https://sigmahq.io/docs/basics/modifiers.html`, pySigma 2.1.0
  taxonomy); Phase 1 evaluates bare/`contains`/`startswith`/`endswith`,
  the structural flags (`cased`, `all`, `exists`) and the value views
  (`windash`, `wide`/`utf16`/`utf16be`, `base64`, `base64offset`).
  Chains with several matchers fail closed (no silent shadowing);
  `exists` loads only standalone with a boolean value (`Load_Bad_Value`
  otherwise). Everything else (`re`, wildcards, `cidr`, comparisons,
  `fieldref`, `expand`, `near`, `aggregation`) answers
  `Error_Unsupported_*` — fail-closed, never silently ignored.
- Value views are derived in the boundary (auditable, SPARK off);
  the core matches over the derived bytes with the existing linear
  matchers, so the proven TCB stays small. `windash` is the exception:
  it cannot pre-derive (5-way expansion is combinatorial), so the core
  runs stride-aware matcher variants keyed off `Mod_Windash` with
  boundary-computed placeholder positions. Placeholder rule mirrors
  pySigma `\B[-/]\b` with an ASCII `[A-Za-z0-9_]` word class
  (documented divergence for non-ASCII). `utf16` is UTF-16LE with a
  BOM (`FF FE`); `base64offset` is exactly pySigma's 3-phase
  construction and its alternatives stay OR-linked even under `all`.
  `base64offset` requires a single value — lists with it are refused
  at load (`Load_Unsupported_Chain`), as are `utf16le` (not a
  canonical pySigma token) and views over integers.
- `Compiled_Rule` static size is dominated by the view tables
  (~1KB per value slot); `Empty_Rule` copies are avoided on hot paths
  (in-place `Clear_Rule`) so worst-case-capacity rules stay inside a
  default 8 MB stack. Deployments that shrink capacities must keep
  `Max_View_Length >= 2 * Max_Value_Length + 2` or wide derivations
  fail with `Load_Too_Long`.
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
