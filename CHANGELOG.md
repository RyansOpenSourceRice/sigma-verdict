# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Generic SPARK Silver core: bounded selections, `contains`/`startswith`/
  `endswith` linear matchers, condition trees with `1 of`/`all of`.
- adayaml boundary loader with explicit `Load_Error` on any lossy input.
- Smoke tests (core + YAML end-to-end) and `tests/corpus/4728_whoami.yml`.
- Proof harness `proof/spark_core.gpr` (flow proved; silver in progress).
