#!/usr/bin/env bash
# Degradation 1: a legacy artifact without a content identity block must
# be explicitly flagged as not attributable while still yielding the raw
# difference list.  Missing identity is never treated as "same content".
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e
require "$PREFERRED_PYTHON" || return 255

base=$(mktemp); mutants=$(mktemp -d); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
"$PREFERRED_PYTHON" -I "$identity_dir/make_mutants.py" "$base" "$mutants"

! grep -q "content-identity" "$mutants/legacy.xml"

rc=$(identity_diff "$mutants/legacy.xml" "$base" "" "$txt")
[ "$rc" == "0" ]
grep -qi "content identity missing" "$txt"
grep -q "side=unknown" "$txt"
# raw rule difference list is still produced, keyed by rule id
grep -q "key=id:xccdf_org.test_rule_a" "$txt"

rm -rf "$mutants"; rm -f "$base" "$txt"
