#!/usr/bin/env bash
# Scenario 6: a value/selection change introduced by a tailoring profile
# is recorded in the identity and attributed as tailoring-introduced.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

base=$(mktemp); tailored=$(mktemp); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
( cd "$identity_dir" && $OSCAP xccdf eval \
	--tailoring-file "$identity_dir/custom.tailoring.xml" \
	--profile xccdf_org.identity_profile_custom \
	--results "$tailored" "v1.xccdf.xml" ) >/dev/null 2>&1 || true

# the tailoring block is present with a digest and the customization entry
grep -q "<cid:tailoring" "$tailored"
grep -q 'kind="select"' "$tailored"
grep -q 'idref="xccdf_org.test_rule_a"' "$tailored"
grep -q 'customized="true"' "$tailored"
grep -q 'benchmark-digest="[0-9a-f]\{64\}"' "$tailored"

rc=$(identity_diff "$base" "$tailored" "" "$txt")
[ "$rc" == "0" ]
grep -q "tailoring-introduced" "$txt"

rm -f "$base" "$tailored" "$txt"
