# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Wildcards and regex (P3a), end to end: implicit unescaped `*`/`?`
  route plain values to the pattern path (bare glob full-matches,
  `contains`/`startswith`/`endswith` tighten anchoring); `re`
  implements the spec PCRE subset (literals, `.` `^$` `*` `+` `?`
  `{n,m}`, classes with ranges and negation, alternation, grouping,
  `i`/`m`/`s` subflags) on a single-pass Pike VM over boundary-
  compiled NFA bytecode. New public surface: `NFA_Program`
  (bytecode + anchor/fold flags), `E_Pattern_List`, `Has_Re_Modifier`,
  `Has_Pattern_Modifier`, `Max_Pattern_Code` capacity,
  `Load_Unsupported_Pattern` (names the offending offset; the SPEC
  growing-subset table tracks what is still refused). Malformed
  patterns are `Load_Bad_Value`; `re`/globs over integers are
  `Load_Bad_Value`; literal values now unescape Sigma backslashes
  at load (`a\*b` denotes `a*b`).
- Numeric comparisons (`gt`/`gte`/`lt`/`lte`) on the integer path,
  end to end: bare plain integers only, else `Load_Bad_Integer`;
  lists OR by default and AND with `all`. New public surface:
  `E_CIDR`/`E_CIDR_List`, `IP_Network` matching, `Comparison_Of`.
- CIDR prefix matching (v4 + full v6) via the new standalone
  `Sigma_Verdict.IP` seam unit (see DESIGN.md "Library seams"):
  strict dotted quads, single-`::` compression, embedded IPv4,
  bare-IP full prefixes; host bits mask leniently (documented
  divergence from pySigma strictness), everything ambiguous fails
  closed. New loader errors: none (malformed networks reuse
  `Load_Bad_Value`, mixed operators reuse `Load_Unsupported_Chain`).
- Value-view modifiers end to end: `windash` (placeholder-exact
  5-way class, stride-aware matchers), `wide`/`utf16`/`utf16be`
  (NUL-interleaved views, BOM for `utf16`), `base64` (encoded-only)
  and `base64offset` (exact 3-phase alternatives, OR-linked even
  under `all`). New public surface: `View_Text`/`To_View_Text`,
  `Mod_UTF16`, view legality in `Chain_Supported`, `Field_Views`,
  `Load_Unsupported_Chain` (base64offset over lists), `Max_View_Length`
  capacity. Canonical pySigma 2.1.0 tokens only: `utf16le` now loads
  as `Load_Unknown_Modifier`; views over integers are `Load_Bad_Value`.
### Fixed
- YAML list values now accumulate on the owning selection frame
  (scalars arrive while the sequence's skip frame is on top) and
  `Add_List_Item` converts before counting: previously every YAML
  list loaded empty with phantom slots, so list rules could never
  match (found by the new `contains|all` end-to-end test).
- `Field_Name` now carries `Dynamic_Predicate (Length <= Max_Field_Length)`:
  out-of-range names fail fast at construction instead of surfacing as
  unprovable slices (closes silver high + 2 mediums). `Value_Text`,
  `Event_Text` and `Pattern_Text` carry the same bound invariant
  (closes the `Text_Matches`-site slice mediums).
- `Ends_With_At` loop carries an `Offset + K` bound invariant for the
  silver prover (closes 8 mediums).
- `Ends_With_At` elaborates its offset only after the length guards: a
  needle longer than the haystack returns no-match instead of raising
  `Constraint_Error` (found by silver level 2; regression-covered in
  `smoke`).
### Added
- `cased` (case-sensitive matching), `all` (list conjunction) and
  `exists` (standalone boolean presence) modifiers, end to end from
  YAML. Chains with more than one matcher token now fail closed as
  `Unsupported` instead of last-wins; malformed `exists` rules are
  rejected at load with the new `Load_Bad_Value`.
- Generic SPARK Silver core: bounded selections, `contains`/`startswith`/
  `endswith` linear matchers, condition trees with `1 of`/`all of`.
- adayaml boundary loader with explicit `Load_Error` on any lossy input.
- Smoke tests (core + YAML end-to-end) and `tests/corpus/4728_whoami.yml`.
- Proof harness `proof/spark_core.gpr` (flow proved; silver in progress).
