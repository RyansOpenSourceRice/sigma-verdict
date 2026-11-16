# AGENTS.md

Instructions for agentic coding contributors (humans: see README.md).

## Commands

```sh
eval "$(alr printenv)"
alr build
sh scripts/alr-test.sh
gnatprove -P proof/spark_core.gpr --mode=flow
sh scripts/verify.sh
pre-commit run --all-files
```

## Rules

- Ada 2022, `SPARK_Mode => On` on every `src/` unit; `boundary/` stays
  `SPARK_Mode (Off)` (adayıml adapter, unprovable by design).
- Bounded strings only; overflow is an explicit error, never truncation.
- Full `Modifier_Kind` enumeration stays designed-in; unevaluated
  modifiers answer `Unsupported`, never silently ignored.
- Public API changes require a `SPECIFICATION.md` delta + CHANGELOG entry.
- No new schedules on shared runners (capacity awareness); CI shape:
  `pre-commit` gate (Betterleaks + Codespell), `test`,
  `sast`/OpenGrep; Trivy/Nyx/Plumbline only when their surface exists,
  else a `DESIGN.md` skip reason.
- After finishing code work: push branch + create/update PR automatically.
- Prefer GitHub MCP for push/PR when CLI git lacks credentials.

## Layout (model: pcapng-in-ada + shacl-ada)

`src/` SPARK core, `boundary/` YAML adapter, `proof/` proof-only GPR
(`spark_core.gpr` + `units/`) that never sees `boundary/`,
`tests/` GPR + corpus, `examples/`, `scripts/` (`alr-test.sh`,
`verify.sh`).
