# SPECIFICATION.md — sigma-verdict (public API delta log)

## 0.1.0-dev (in development, unreleased)
- `Sigma_Verdict.Engine` (generic): `Detection` subset —
  `Selection` (EventID integer equality, `CommandLine`
  `contains`/`startswith`/`endswith` ASCII case-insensitive),
  condition trees (`selection`, `AND`/`OR`/`NOT`, `1 of`/`all of`).
- `Sigma_Verdict.Boundary.Load_Detection`: YAML text to
  `Compiled_Rule`; metadata (`title`/`id`/`logsource`) accepted and
  ignored; every lossy case is a `Load_Error`.
- Public API stability is NOT promised before 0.1.0.
- `Field_Name` carries `Dynamic_Predicate (Length <= Max_Field_Length)`:
  only constructor-built names are valid; out-of-range `Length` fails
  fast instead of producing unprovable slices.

## Subset table (Sigma 2.x target; see ROADMAP.md for phases)

| Surface | Phase 1 (now) | Later |
|---|---|---|
| Matchers: exact, `contains`, `startswith`, `endswith` | evaluate | — |
| Flags: `cased`, `all`, `exists` | evaluate | — |
| Views: `windash`, `wide`/`utf16`/`utf16be`, `base64`, `base64offset` | evaluate | — |
| Illegal chains (several matchers, mixed views, patterns) | `Unsupported` | — |
| `utf16le` (non-canonical), views over integers, `base64offset` over lists | `Load_Unknown_Modifier` / `Load_Bad_Value` / `Load_Unsupported_Chain` | — |
| `gt`/`gte`/`lt`/`lte`, `cidr` (v4+v6) | `Unsupported` | P2 |
| Wildcards (implicit + explicit), `re` subset, `fieldref`, `expand` | `Unsupported` | P3 |
| Conditions: `AND`/`OR`/`NOT`, `1 of`/`all of`, parens, `count()` | parens/`count()` `Unsupported` | P4 |
| `near` | `Unsupported` (deferred, not opposed) | — |
| Correlations | out of scope | P5 (new stateful generic) |

## Changing this file
Any public API change requires a `SPECIFICATION.md` delta entry plus
a `CHANGELOG.md` entry in the same commit.
