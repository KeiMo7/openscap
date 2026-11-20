#!/usr/bin/env bash
# Tests for host identity resolution and merging of multi-host / multi-scan
# XCCDF results.
. $builddir/tests/test_common.sh

set -e
set -o pipefail

name=$(basename $0 .sh)
tmpdir=$(mktemp -d)
result="$tmpdir/merged.xml"
out="$result"
stderr="$tmpdir/stderr.log"

function cleanup {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

# Merge the given inputs into $out.  Any failure aborts the test.
function merge {
    : > "$stderr"
    $OSCAP xccdf merge-results --output "$out" "$@" 2> "$stderr"
}

# ---------------------------------------------------------------------------
# 1. Multiple scans of the same host collapse to one host view that keeps the
#    time, scanner version and verdict summary of every scan.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_morning.xml"
assert_exists 1 '//TestResult'
assert_exists 2 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:scan"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:scan"][contains(text(), "1.4.7")]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:scan"][contains(text(), "1.4.8")]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:scan_count"]/text()[.="2"]'
# start-time/end-time span the whole history
assert_exists 1 '//TestResult[@start-time="2026-11-19T22:00:00+00:00"]'
assert_exists 1 '//TestResult[@end-time="2026-11-20T06:05:00+00:00"]'
# latest conclusion is visible
assert_exists 1 '//TestResult/rule-result[@idref="xccdf_com.example_rule_two"]/result[text()="pass"]'
# history carries the earlier conclusion
assert_exists 1 '//rule-result[@idref="xccdf_com.example_rule_two"]/message[contains(text(), "fail|pass")]'

# ---------------------------------------------------------------------------
# 2. Identity is traceable: the resolved identity and its source are facts.
# ---------------------------------------------------------------------------
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id"][text()="hostname:web1"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id_source"][text()="hostname"]'
# stable identifiers take precedence over host names
merge "$srcdir/scan_db1.xml"
assert_exists 1 '//TestResult/target[text()="db1"]'

# A stable identifier takes precedence over the host name: the host is
# merged even though the name changed completely.
merge "$srcdir/scan_stable_id_1.xml" "$srcdir/scan_stable_id_2.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id"][text()="stable:machine-7f3a"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id_source"][text()="stable"]'
assert_exists 1 '//TestResult/target[text()="legacy-name"]'
assert_exists 1 '//TestResult/target[text()="new-name"]'

# An address is the weakest identity: it is used when nothing stronger is
# available, but it still groups repeated scans of the same address.
merge "$srcdir/scan_address_only_1.xml" "$srcdir/scan_address_only_2.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id"][text()="address:203.0.113.7"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id_source"][text()="address"]'

# An address alone never overrides a stronger identity: two records that name
# different hosts are kept apart even when the address matches.
cat > "$tmpdir/address_reuse_a.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_testresult_reuse_a" end-time="2026-11-19T10:00:00+00:00">
  <target>host-a</target>
  <target-address>203.0.113.9</target-address>
  <rule-result idref="xccdf_com.example_rule_one" time="2026-11-19T10:00:00+00:00" weight="1.0" severity="high"><result>pass</result></rule-result>
</TestResult>
XML
cat > "$tmpdir/address_reuse_b.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_testresult_reuse_b" end-time="2026-11-19T11:00:00+00:00">
  <target>host-b</target>
  <target-address>203.0.113.9</target-address>
  <rule-result idref="xccdf_com.example_rule_one" time="2026-11-19T11:00:00+00:00" weight="1.0" severity="high"><result>fail</result></rule-result>
</TestResult>
XML
merge "$tmpdir/address_reuse_a.xml" "$tmpdir/address_reuse_b.xml"
assert_exists 2 '//TestResult'

# ---------------------------------------------------------------------------
# 3. Renaming a host (FQDN -> short name) keeps it one host.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_renamed.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/target[text()="web1"]'
assert_exists 1 '//TestResult/target[text()="web1.example.com"]'

# ---------------------------------------------------------------------------
# 4. Address changes do not create a new host and all addresses are kept.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_new_address.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/target-address[text()="10.0.0.1"]'
assert_exists 1 '//TestResult/target-address[text()="172.16.0.10"]'

# ---------------------------------------------------------------------------
# 5. A recycled address must NOT merge two different machines.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_recycled_address_a.xml" "$srcdir/scan_recycled_address_b.xml"
assert_exists 2 '//TestResult'
assert_exists 1 '//TestResult/target[text()="old-host"]'
assert_exists 1 '//TestResult/target[text()="new-host"]'

# ---------------------------------------------------------------------------
# 6. Repeated reporting of the same rule in one batch is deduplicated while
#    the time series and the counts stay correct.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_duplicate_reports.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/rule-result[@idref="xccdf_com.example_rule_one"]'
assert_exists 1 '//rule-result[@idref="xccdf_com.example_rule_one"]/result[text()="fail"]'
assert_exists 1 '//rule-result[@idref="xccdf_com.example_rule_one"]/message[contains(text(), "count=2")]'
assert_exists 1 '//rule-result[@idref="xccdf_com.example_rule_one"]/message[contains(text(), "first=2026-11-19T10:01:00+00:00")]'
assert_exists 1 '//rule-result[@idref="xccdf_com.example_rule_one"]/message[contains(text(), "last=2026-11-19T12:01:00+00:00")]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:scan_count"][text()="3"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:rule_count"][text()="1"]'

# ---------------------------------------------------------------------------
# 7. A single input with several host records is read completely (the first
#    record must not be the only one imported).
# ---------------------------------------------------------------------------
merge "$srcdir/scan_multiple_hosts_one_file.xml"
assert_exists 3 '//TestResult'
assert_exists 1 '//TestResult/target[text()="alpha"]'
assert_exists 1 '//TestResult/target[text()="beta"]'
assert_exists 1 '//TestResult/target[text()="gamma"]'

# ---------------------------------------------------------------------------
# 8. Deterministic output: file order and batch split do not matter.
# ---------------------------------------------------------------------------
a="$tmpdir/a.xml"
b="$tmpdir/b.xml"
$OSCAP xccdf merge-results --output "$a" "$srcdir/scan_web1_night.xml" "$srcdir/scan_db1.xml" "$srcdir/scan_web1_morning.xml" 2>/dev/null
$OSCAP xccdf merge-results --output "$b" "$srcdir/scan_web1_morning.xml" "$srcdir/scan_db1.xml" "$srcdir/scan_web1_night.xml" 2>/dev/null
cmp -s "$a" "$b"

# Two-step merge (import the intermediate result again) equals the one-shot
# merge: the merged document carries enough information to be re-merged.
c="$tmpdir/c.xml"
$OSCAP xccdf merge-results --output "$c" "$a" 2>/dev/null
cmp -s "$a" "$c"

# Adding a further scan to an already merged document is equivalent to
# merging everything at once, no matter how the batch is split.
d="$tmpdir/d.xml"
e="$tmpdir/e.xml"
f="$tmpdir/f.xml"
$OSCAP xccdf merge-results --output "$d" "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_morning.xml" 2>/dev/null
$OSCAP xccdf merge-results --output "$e" "$srcdir/scan_web1_new_address.xml" 2>/dev/null
$OSCAP xccdf merge-results --output "$f" "$d" "$e" 2>/dev/null
$OSCAP xccdf merge-results --output "$tmpdir/g.xml" "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_morning.xml" "$srcdir/scan_web1_new_address.xml" 2>/dev/null
cmp -s "$f" "$tmpdir/g.xml"

# ---------------------------------------------------------------------------
# 9. Unknown identity is counted separately and never merged with named hosts.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_unknown_1.xml" "$srcdir/scan_unknown_2.xml" "$srcdir/scan_web1_night.xml"
assert_exists 2 '//TestResult'
assert_exists 1 '//TestResult/target[text()="unknown"]'
assert_exists 1 '//TestResult/target[text()="web1.example.com"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id"][text()="unknown"]'

# ---------------------------------------------------------------------------
# 10. Identity conflicts keep both machines and flag them.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_conflict_1.xml" "$srcdir/scan_conflict_2.xml"
assert_exists 2 '//TestResult'
assert_exists 2 '//TestResult/target-facts/fact[@name="urn:xccdf:fact:asset:identifier:host_id_conflict"][text()="true"]'

# ---------------------------------------------------------------------------
# 11. A malformed record is skipped and reported; the rest is still merged.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_malformed_mixed.xml"
assert_exists 1 '//TestResult'
assert_exists 1 '//TestResult/target[text()="goodhost.example.com"]'
grep -q "Skipped 1 malformed" "$stderr"

# ---------------------------------------------------------------------------
# 12. Empty input is an explicit error, not an empty report.
# ---------------------------------------------------------------------------
: > "$stderr"
rm -f "$out"
if $OSCAP xccdf merge-results --output "$out" "$srcdir/scan_empty.xml" 2> "$stderr"; then
    echo "Merging an empty input must fail"
    exit 1
fi
[ ! -f "$out" ]

# ---------------------------------------------------------------------------
# 13. The merged document is a valid XCCDF document that the existing report
#     pipeline can read.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_web1_night.xml" "$srcdir/scan_web1_morning.xml" "$srcdir/scan_db1.xml"
$OSCAP xccdf validate --skip-schematron "$out"
$OSCAP info "$out" > "$tmpdir/info.txt" 2> /dev/null
grep -q "Result ID: xccdf_org.open-scap_testresult_host_" "$tmpdir/info.txt"
$OSCAP xccdf generate report --output "$tmpdir/report.html" "$out" 2> /dev/null
grep -q "Rule Overview" "$tmpdir/report.html"

# ---------------------------------------------------------------------------
# 14. Deduplication counts: the same rule reported twice in one batch yields
#     one rule-result whose first/last time and count are correct, and the
#     counters can be recomputed from the details.
# ---------------------------------------------------------------------------
merge "$srcdir/scan_duplicate_reports.xml"
assert_exists 1 '//TestResult/rule-result[@idref="xccdf_com.example_rule_one"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:rule_count"][text()="1"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:fail_count"][text()="1"]'
assert_exists 1 '//TestResult/target-facts/fact[@name="urn:openscap:fact:host:pass_count"][text()="0"]'

# ---------------------------------------------------------------------------
# 15. Inputs are never modified: the merge must not rewrite or delete them.
# ---------------------------------------------------------------------------
cp "$srcdir/scan_web1_night.xml" "$tmpdir/input1.xml"
cp "$srcdir/scan_db1.xml" "$tmpdir/input1-db.xml"
before1=$(cksum < "$tmpdir/input1.xml")
before2=$(cksum < "$tmpdir/input1-db.xml")
merge "$tmpdir/input1.xml" "$tmpdir/input1-db.xml"
[ "$before1" = "$(cksum < "$tmpdir/input1.xml")" ]
[ "$before2" = "$(cksum < "$tmpdir/input1-db.xml")" ]

exit 0
