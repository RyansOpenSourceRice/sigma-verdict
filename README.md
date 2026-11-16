# sigma-verdict
An independent Sigma rule evaluator written in the Ada programming language — parse, validate, and match Sigma detection rules against logs. Not affiliated with or endorsed by AdaCore or the Sigma project.

> **Status: in core development, not yet usable in production tools.**
> Phase 1 evaluates `EventID: 4728` plus `CommandLine|contains/startswith/endswith: 'whoami'` with
> `AND`/`OR`/`NOT` and `1 of`/`all of` conditions. Everything else
> (`re`, wildcards, `windash`/`wide`/`base64*`, comparisons, `near`,
> aggregation) is designed into the AST but answers `Unsupported`
> fail-closed until Phase 2.

## Layout

- `src/` — generic SPARK core (`Sigma_Verdict.Engine`); capacities are
  generic formals, `Sigma_Verdict.Limits` holds reviewed defaults.
- `boundary/` — YAML loader (`Sigma_Verdict.Boundary`, SPARK off);
  every lossy input becomes an explicit `Load_Error`, never truncation.
- `proof/` — proof-only GPR (`spark_core.gpr`) that sees `src/` only.
- `tests/` — `smoke` (core) + `yaml_smoke` (end-to-end) + corpus.
- `examples/` — minimal embedding (`detect_whoami`).

## Quick start

```sh
eval "$(alr printenv)"
alr build
sh scripts/alr-test.sh     # build + run smoke tests
sh scripts/verify.sh       # build + tests + GNATprove flow
```

See `DESIGN.md` for the shape and `SPECIFICATION.md` for the API log.
