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
  never truncation (norm from `pcapng-ada`, `shacl-ada`).
- `contains`/`startswith`/`endswith`: linear scan, ASCII
  case-insensitive fold. No `GNAT.Regpat` (backtracking ReDoS,
  AdaCore Gem #25).
- Integer comparison uses `Integer`; out-of-range magnitudes never
  wrap — the boundary rejects them with `Load_Bad_Integer`, and
  quoted numbers stay text (pySigma types compare operators as
  numeric-only). Type mismatch at match time is a clean non-match,
  mirroring the P1a equality path; event data is untrusted input,
  while a malformed stored rule fails closed as `Unsupported`.
- CIDR matching is exact prefix math over parsed bytes. Host bits
  mask leniently (the formal Sigma spec is silent on host-bits-set
  networks, so operational use wins over pySigma's strict compile
  rejection — documented divergence); everything ambiguous fails
  closed: leading-zero octets (octal trap), zone IDs, multiple `::`,
  bad prefixes. IPv4 sides compare in IPv6 space as `::ffff:0:0/96`,
  so v4 rules/events mix with v6 exactly; malformed event IPs are
  clean non-matches.
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

## Library seams
`Sigma_Verdict.IP` (IP parsing + prefix matching) is built, not
imported: no Alire crate offers a small, SPARK-provable,
dependency-free IP parser (`enet` is an embedded IPv4 stack,
`adare-net`/sockets are runtime-bound and raising, not total), and
the need is ~200 lines with fail-closed total semantics. The unit
is non-generic and depends on nothing else in the crate, so a
future external library replaces two files (`sigma_verdict-ip.ads`
+ `.adb`) without touching core, boundary, tests or proof.
- Seam rules: Engine stores `IP_Network` values and calls only
  `Parse_Address`/`Contains`; Boundary calls only `Parse_Network`
  and maps zero-length results to `Load_Bad_Value`. No dotted-quad,
  hextet, prefix or masking logic may live outside the seam unit.
- Replacement contract: total functions, malformed input yields a
  zero-length network/address (never raises), `Contains` exact over
  the same 4/16-byte + prefix representation, SPARK Silver-clean so
  the core proof holds. Graduation to a standalone Alire crate is an
  explicit non-goal for now (see ROADMAP).

## Non-goals
`re`/wildcard matching (needs Thompson NFA Pike VM, like
`shacl-ada`'s `sh:pattern`), `near`/`aggregation`, multi-document
streams, non-UTF-8 input handling beyond adayaml, graduating
`Sigma_Verdict.IP` to a standalone Alire crate (explicit future,
shaped for by the seam).
