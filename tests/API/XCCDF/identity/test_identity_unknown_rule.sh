#!/usr/bin/env bash
# Degradation 2: a single rule whose content digest cannot be parsed is
# marked unknown; the whole artifact must stay usable and the other
# content is still compared normally.
. $builddir/tests/test_common.sh
. "$srcdir/identity_common.sh"
set -e
require "$PREFERRED_PYTHON" || return 255

base=$(mktemp); bad=$(mktemp); txt=$(mktemp)
identity_eval "$base" "v1.xccdf.xml"

# strip the per-rule digests to simulate a per-rule content parse failure
"$PREFERRED_PYTHON" -I - "$base" "$bad" <<'PYEOF'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
s = re.sub(r' body-digest="[0-9a-f]+"', '', s)
s = re.sub(r' logic-digest="[0-9a-f]+"', '', s)
open(dst, "w", encoding="utf-8").write(s)
PYEOF

# the artifact still parses and carries a component-level identity
grep -q "content-identity" "$bad"
grep -q 'content-type="xccdf"' "$bad"

rc=$(identity_diff "$base" "$bad" "" "$txt")
[ "$rc" == "0" ]
# the single rule is unknown, never a confident content change
grep -qF "[unknown]" "$txt"
grep -q "side=unknown" "$txt"
! grep -q "content-changed" "$txt"

rm -f "$base" "$bad" "$txt"
