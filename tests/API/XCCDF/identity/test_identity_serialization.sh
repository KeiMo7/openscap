#!/usr/bin/env bash
# T1: identical content stored with different serializations must yield
# identical component and rule digests.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

r1=$(mktemp); r2=$(mktemp)
identity_eval "$r1" "v1.xccdf.xml"
identity_eval "$r2" "v1_compact.xccdf.xml"

d1=$(identity_xccdf_digest "$r1")
d2=$(identity_xccdf_digest "$r2")
[ -n "$d1" ]
[ "$d1" == "$d2" ]

b1=$(identity_rule_body_digest "$r1")
b2=$(identity_rule_body_digest "$r2")
[ -n "$b1" ]
[ "$b1" == "$b2" ]

# And the diff of the two must report no difference.
txt=$(mktemp)
rc=$(identity_diff "$r1" "$r2" "" "$txt")
[ "$rc" == "0" ]
grep -q "added=0 disappeared=0 flipped=0" "$txt"
grep -qF "[unchanged]" "$txt"

rm -f "$r1" "$r2" "$txt"
