#!/usr/bin/env bash
# The identity block must travel into an ARF result datastream, survive
# ARF validation, and remain diffable offline from the ARF directly.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

arf1=$(mktemp); arf2=$(mktemp); txt=$(mktemp)
identity_eval_arf "$arf1" "v1.xccdf.xml"
identity_eval_arf "$arf2" "bodychange.xccdf.xml"

grep -q "content-identity" "$arf1"
$OSCAP ds rds-validate "$arf1" >/dev/null 2>&1

# offline diff works directly on ARFs, no rescan, no network
rc=$(identity_diff "$arf1" "$arf2" "" "$txt")
[ "$rc" == "0" ]
grep -Eq "content-changed|content-side" "$txt"

rm -f "$arf1" "$arf2" "$txt"
