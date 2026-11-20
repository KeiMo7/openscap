#!/usr/bin/env bash
# T6: author version changes but the rule body is byte-identical after
# canonicalization.  Must be reported as version-label-only, never as a
# decision/content change.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e

base=$(mktemp); bumped=$(mktemp); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"
identity_eval "$bumped" "versiononly.xccdf.xml"

grep -q 'author-version="1.0"' "$base"
grep -q 'author-version="2.0"' "$bumped"

# body digest is stable despite the version bump
[ "$(identity_rule_body_digest "$base")" == "$(identity_rule_body_digest "$bumped")" ]

rc=$(identity_diff "$base" "$bumped" "" "$txt")
[ "$rc" == "0" ]
grep -q "version-label-only" "$txt"
! grep -q "content-side" "$txt"
! grep -q "result-flip" "$txt"

rm -f "$base" "$bumped" "$txt"
