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

## Changing this file
Any public API change requires a `SPECIFICATION.md` delta entry plus
a `CHANGELOG.md` entry in the same commit.
