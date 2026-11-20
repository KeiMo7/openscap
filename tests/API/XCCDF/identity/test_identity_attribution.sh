#!/usr/bin/env bash
# T4: one target-side flip and one content-side flip, each attributed in
# the correct direction; the comparison is byte-for-byte reproducible.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e
require "$PREFERRED_PYTHON" || return 255

base=$(mktemp); logic=$(mktemp); mutants=$(mktemp -d)
identity_eval "$base" "v1.xccdf.xml"
identity_eval "$logic" "logicchange.xccdf.xml"
"$PREFERRED_PYTHON" -I "$identity_dir/make_mutants.py" "$base" "$mutants"

# --- target side: identical content, only the recorded outcome flips ---
tt=$(mktemp)
rc=$(identity_diff "$base" "$mutants/targetflip.xml" "" "$tt")
[ "$rc" == "0" ]
grep -qF "[result-flip]" "$tt"
grep -q "side=target-side" "$tt"
grep -q "flipped=1" "$tt"

# --- content side: decision criteria change (logic digest) ---
tc=$(mktemp)
rc=$(identity_diff "$base" "$logic" "" "$tc")
[ "$rc" == "0" ]
grep -Eq "content-changed|content-side" "$tc"
# the reason must name the triggering decision criterion
grep -q "check-content-ref changed" "$tc"
grep -q "oval:org.test:def:1" "$tc"
grep -q "oval:org.test:def:2" "$tc"
# logic digests must actually differ
[ "$(identity_rule_logic_digest "$base")" != "$(identity_rule_logic_digest "$logic")" ]

# --- reproducibility: run twice, text and XML must be identical bytes ---
t1=$(mktemp); t2=$(mktemp); x1=$(mktemp); x2=$(mktemp)
identity_diff "$base" "$logic" "$x1" "$t1" >/dev/null
identity_diff "$base" "$logic" "$x2" "$t2" >/dev/null
cmp "$t1" "$t2"
cmp "$x1" "$x2"

rm -rf "$mutants"
rm -f "$base" "$logic" "$tt" "$tc" "$t1" "$t2" "$x1" "$x2"
