#!/bin/sh
#  scripts/verify.sh — full local gate: build + tests + flow proof.
#  Flow (proved) is the blocking gate; silver level 2 runs separately
#  in CI (prove-silver, non-blocking) — see DESIGN.md.
#  All alr invocations are non-interactive (-n) so this also runs on
#  fresh machines/CI with no toolchain or indexes installed yet.
set -eu
eval "$(alr -n printenv)"
alr -n build
sh scripts/alr-test.sh
gnatprove -P proof/spark_core.gpr --mode=flow
echo "verify: build + tests + flow proof green"
