# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
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
