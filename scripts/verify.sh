#!/bin/sh
#  scripts/verify.sh — full local gate: build + tests + flow proof.
#  Silver level 2 is attempted with a bounded budget; flow (proved) is
#  the blocking gate until silver closes (see DESIGN.md).
set -eu
eval "$(alr printenv)"
alr -n build
sh scripts/alr-test.sh
gnatprove -P proof/spark_core.gpr --mode=flow
echo "verify: build + tests + flow proof green"
