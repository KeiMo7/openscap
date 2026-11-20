#!/usr/bin/env bash
# T3: a renamed rule and a rule moved into a group must be matched by
# their stable identity, not reported as an unrelated add + remove pair.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

base=$(mktemp); renamed=$(mktemp); moved=$(mktemp)
tr=$(mktemp); tm=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
identity_eval "$renamed" "renamed.xccdf.xml"
identity_eval "$moved" "moved.xccdf.xml"

rc=$(identity_diff "$base" "$renamed" "" "$tr")
[ "$rc" == "0" ]
# exactly one matched entry, renamed - never add/remove
grep -qF "[renamed]" "$tr"
! grep -q "added=" "$tr" || grep -q "added=0" "$tr"
grep -q "disappeared=0" "$tr"
grep -q "old-id=xccdf_org.test_rule_a " "$tr"
grep -q "new-id=xccdf_org.test_rule_a_renamed" "$tr"

rc=$(identity_diff "$base" "$moved" "" "$tm")
[ "$rc" == "0" ]
grep -qF "[moved]" "$tm"
grep -q "disappeared=0" "$tm"
# same id retained across the move
grep -q "old-id=xccdf_org.test_rule_a new-id=xccdf_org.test_rule_a" "$tm"

rm -f "$base" "$renamed" "$moved" "$tr" "$tm"
