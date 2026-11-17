#!/bin/sh
#  scripts/verify.sh — full local gate: build + tests + flow proof.
#  Flow (proved) is the blocking gate in this script; silver level 2
#  additionally runs in CI (prove-silver) and must be clean before
#  merge, so run it locally too:
#    gnatprove -P proof/spark_core.gpr --mode=silver --level=2 \
#      --checks-as-errors=on
#  All alr invocations are non-interactive (-n) so this also runs on
#  fresh machines/CI with no toolchain or indexes installed yet.
set -eu
eval "$(alr -n printenv)"
alr -n build
sh scripts/alr-test.sh
gnatprove -P proof/spark_core.gpr --mode=flow
echo "verify: build + tests + flow proof green"
