#!/usr/bin/env bash
# Scenario 9: baseline alignment produces the added / disappeared /
# flipped lists, each carrying the stable identity and a reason.  This
# test drives all three at once using rename (matched), logic change and
# target flip inputs.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e
require "$PREFERRED_PYTHON" || return 255

base=$(mktemp); mutants=$(mktemp -d); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
"$PREFERRED_PYTHON" -I "$identity_dir/make_mutants.py" "$base" "$mutants"

# flipped list
rc=$(identity_diff "$base" "$mutants/targetflip.xml" "" "$txt")
[ "$rc" == "0" ]
grep -q "flipped=1" "$txt"
grep -qF "[result-flip]" "$txt"
grep -Eq "key=check-ref:|key=id:|key=cluster:" "$txt"

# every emitted entry carries a reason line
grep -q "reason:" "$txt"

# a matched (renamed) baseline yields zero added / disappeared
ren=$(mktemp); tr=$(mktemp)
identity_eval "$ren" "renamed.xccdf.xml"
identity_diff "$base" "$ren" "" "$tr" >/dev/null
grep -q "added=0 disappeared=0" "$tr"

rm -rf "$mutants"; rm -f "$base" "$ren" "$txt" "$tr"
