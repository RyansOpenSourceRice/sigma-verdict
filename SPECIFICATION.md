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
| Illegal chains (several matchers, mixed views, mixed operators) | `Unsupported` | — |
| `utf16le` (non-canonical), views over integers, `base64offset` over lists | `Load_Unknown_Modifier` / `Load_Bad_Value` / `Load_Unsupported_Chain` | — |
| `gt`/`gte`/`lt`/`lte`, `cidr` (v4+v6) | evaluate | — |
| `neq` | `Unsupported` (no token mapped; not in P2 scope) | — |
| Wildcards: implicit unescaped `*`/`?` (glob; no explicit token in 2.x) | evaluate (NFA; bare full-match, matcher tokens anchor) | — |
| `re` spec PCRE subset: literals, `.` `^$` `*` `+` `?` `{n,m}`, classes `[a-z]` `[^a-z]`, alternation, grouping, `i`/`m`/`s` subflags | evaluate (Thompson NFA, single-pass Pike VM; bare `re` searches) | — |
| `re` PCRE escapes `\n` `\t` `\r` `\\` plus escaped metacharacters | evaluate (literals/controls) | — |
| `re` outside the spec subset (backrefs, lookarounds, shorthand classes, `\b`, lazy/possessive quantifiers, `{n,m}`-on-assertion) | `Load_Unsupported_Pattern` (Detail = offending offset; subset grows, see below) | growing |
| Malformed patterns (dangling `\`, leading quantifier, stacked quantifiers, unclosed class/group, bad range) | `Load_Bad_Value` | — |
| `re`/glob over integers, mixed int/text pattern lists | `Load_Bad_Value` | — |
| `cased` + `re|i`, patterns + views/comparisons/cidr, duplicate pattern sources | `Unsupported` (refused chain) | — |
| Literal backslash escapes in plain values (`\*` `\?` `\\`) | unescaped at load (`a\*b` denotes `a*b`) | — |
| `fieldref`, `expand` | `Unsupported` | P3b |
| Conditions: `AND`/`OR`/`NOT`, `1 of`/`all of`, parens, `count()` | parens/`count()` `Unsupported` | P4 |
| `near` | `Unsupported` (deferred, not opposed) | — |
| Correlations | out of scope | P5 (new stateful generic) |

## Growing pattern subset (P3a transparency log)

`Load_Unsupported_Pattern` names the rule's offset where evaluation
stops. Each entry is a commit to build out, not a permanent refusal:

- Shorthand classes (`\d` `\w` `\s` and negations), `\b` word
  boundary, backreferences, lookarounds/lookbehinds, lazy and
  possessive quantifiers, `{n,m}` on `^`/`$` assertions.
- PCRE-lenient fallbacks (documented, fail-closed toward non-match):
  invalid `{n,m}` forms read literally (`a{2,1}` matches `a{2,1}`);
  unmatched `)` reads literally; `$` also matches before a final
  LF (PCRE `$` semantics, with and without `m`).

## Changing this file
Any public API change requires a `SPECIFICATION.md` delta entry plus
a `CHANGELOG.md` entry in the same commit.
