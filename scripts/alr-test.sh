#!/bin/sh
#  Test action for `alr test`: build and run the smoke test.
set -eu
eval "$(alr -n printenv)"
gprbuild -q -p -P tests/tests.gpr
./tests/bin/smoke
./tests/bin/yaml_smoke
echo "smoke: all checks passed"
