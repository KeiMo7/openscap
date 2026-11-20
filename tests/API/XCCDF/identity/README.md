# Content identity tests

These tests exercise the content-derived identity embedded in XCCDF 1.2
TestResult documents (the `cid` namespace) and the offline
`oscap xccdf diff` attribution command.

## Fixtures

Generated deterministically by `gen_fixtures.py` (run with `python3 -I`):

| fixture                | difference from `v1.xccdf.xml`                          |
|------------------------|---------------------------------------------------------|
| `v1.xccdf.xml`         | baseline rule                                           |
| `v1_compact.xccdf.xml` | identical content, different serialization (no indent) |
| `bodychange.xccdf.xml` | title/description changed, author version unchanged     |
| `versiononly.xccdf.xml`| author version bumped, rule body identical              |
| `renamed.xccdf.xml`    | rule `@id` changed, OVAL anchor unchanged               |
| `moved.xccdf.xml`      | rule moved into a Group, `@id` unchanged                |
| `logicchange.xccdf.xml`| check-content-ref target changed (decision criteria)    |

`make_mutants.py` derives result-only mutations (target flip, legacy
artifact, different target, tailoring mismatch) from a generated scan
result without rescanning anything.

## Tests

| script                              | requirement covered                                   |
|-------------------------------------|-------------------------------------------------------|
| `test_identity_serialization.sh`    | T1, hard constraint 2 (C14N stable across serialization) |
| `test_identity_body_change.sh`      | T2, scenario 2 (body changed, version unchanged)      |
| `test_identity_version_only.sh`     | scenario 3 (version label only)                       |
| `test_identity_rename_move.sh`      | T3, scenario 5 (stable identity matching)             |
| `test_identity_attribution.sh`      | T4, scenarios 4/7, hard constraint 5 (reproducibility)|
| `test_identity_legacy.sh`           | degradation 1, scenario 10 (missing identity)         |
| `test_identity_unknown_rule.sh`     | degradation 2 (per-rule unknown)                      |
| `test_identity_gates.sh`            | degradation 3 & 4 (tailoring mismatch, incomparable)  |
| `test_identity_arf.sh`              | ARF end-to-end, offline, scenario 8                   |
| `test_identity_baseline_lists.sh`   | scenario 9 (added/disappeared/flipped lists)          |
| `test_identity_tailoring.sh`        | scenario 6 (tailoring-introduced difference)          |

Eval commands run inside the fixture directory because the XCCDF
content references OVAL files with relative hrefs.
