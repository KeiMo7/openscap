#!/usr/bin/env bash
# Degradation 3 & 4:
#  - incomparable targets -> refuse attribution, exit code 2, raw list only
#  - tailoring/content digest mismatch -> error, exit code 3, no guessing
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e
require "$PREFERRED_PYTHON" || return 255

base=$(mktemp); mutants=$(mktemp -d); txt=$(mktemp); rep=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
"$PREFERRED_PYTHON" -I "$identity_dir/make_mutants.py" "$base" "$mutants"

# Target incomparability: exit code 2
rc=$(identity_diff "$base" "$mutants/othertarget.xml" "" "$txt")
[ "$rc" == "2" ]
grep -qi "not comparable" "$txt"
grep -q "side=unknown" "$txt"

# same gate reflected in the XML report
rc=$(identity_diff "$base" "$mutants/othertarget.xml" "$rep" "$txt")
[ "$rc" == "2" ]
grep -q 'status="target-incomparable"' "$rep"

# Tailoring mismatch: exit code 3, names the mismatching fields
rc=$(identity_diff "$base" "$mutants/tailormismatch.xml" "" "$txt")
[ "$rc" == "3" ]
grep -qi "tailoring" "$txt"
grep -qi "mismatch" "$txt"
grep -q "benchmark-digest" "$txt"

rm -rf "$mutants"; rm -f "$base" "$txt" "$rep"
