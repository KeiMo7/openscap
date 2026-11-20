# Shared helpers for content-identity tests.  Sourced by each test_*.sh.
# Not a standalone test.

identity_dir="$srcdir"

# Run an eval tolerating the exit code 2 that simply means a rule failed.
# Relative OVAL hrefs resolve against the fixture directory, so every eval
# runs with that as its working directory; output paths stay absolute.
identity_eval() {
	local out="$1"; shift
	# $OSCAP intentionally unquoted: it may be a wrapper command plus binary.
	( cd "$identity_dir" && $OSCAP xccdf eval --results "$out" "$@" ) 2>/dev/null || true
}

# As identity_eval but writes an ARF result datastream.
identity_eval_arf() {
	local out="$1"; shift
	( cd "$identity_dir" && $OSCAP xccdf eval --results-arf "$out" "$@" ) 2>/dev/null || true
}

# Extract the XCCDF component digest from a result artifact.
identity_xccdf_digest() {
	grep -oE 'content-type="xccdf" digest="[0-9a-f]+"' "$1" \
		| head -1 | sed -E 's/.*digest="([0-9a-f]+)".*/\1/'
}

# Extract the body-digest of the single test rule.
identity_rule_body_digest() {
	grep -oE '<cid:rule[^>]*body-digest="[0-9a-f]+"' "$1" \
		| head -1 | sed -E 's/.*body-digest="([0-9a-f]+)".*/\1/'
}

# Extract the logic-digest of the single test rule.
identity_rule_logic_digest() {
	grep -oE '<cid:rule[^>]*logic-digest="[0-9a-f]+"' "$1" \
		| head -1 | sed -E 's/.*logic-digest="([0-9a-f]+)".*/\1/'
}

# Run the diff command and capture text, report, and exit code separately.
identity_diff() {
	local old="$1" new="$2" report="$3" textout="$4"
	set +e
	if [ -n "$report" ]; then
		$OSCAP xccdf diff --report "$report" "$old" "$new" > "$textout" 2>/dev/null
	else
		$OSCAP xccdf diff "$old" "$new" > "$textout" 2>/dev/null
	fi
	local rc=$?
	set -e
	echo "$rc"
}
