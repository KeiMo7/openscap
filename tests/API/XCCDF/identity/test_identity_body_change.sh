#!/usr/bin/env bash
# T2: rule body changes while the author version string stays "1.0".
# The two artifacts must be distinguishable and attributed to the content side.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

base=$(mktemp); changed=$(mktemp); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
identity_eval "$changed" "bodychange.xccdf.xml"

# author version unchanged on both
grep -q 'author-version="1.0"' "$base"
grep -q 'author-version="1.0"' "$changed"

# but the body digests differ
[ "$(identity_rule_body_digest "$base")" != "$(identity_rule_body_digest "$changed")" ]

rc=$(identity_diff "$base" "$changed" "" "$txt")
[ "$rc" == "0" ]
# not mislabeled as a pure version bump
! grep -q "version-label-only" "$txt"
grep -Eq "content-changed|content-side" "$txt"

rm -f "$base" "$changed" "$txt"
