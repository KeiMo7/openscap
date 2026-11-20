#!/usr/bin/env python3
"""Generate deterministic XCCDF/OVAL fixtures for content-identity tests.

Run with: python3 -I gen_fixtures.py <output_dir>

Variants:
  - v1 / v1_compact: identical content, different serialization
  - bodychange: rule body text changed, author version unchanged
  - versiononly: author version changed, rule body unchanged
  - renamed: rule @id changed, OVAL definition anchor unchanged
  - moved: rule moved into a Group, @id unchanged
  - logicchange: check-content-ref target changed (decision criteria)
All OVAL files are constant and deterministic (no timestamps).
"""
import os
import sys

BENCH_ID = "xccdf_org.test_benchmark_id"
RULE_ID = "xccdf_org.test_rule_a"
RULE_ID_RENAMED = "xccdf_org.test_rule_a_renamed"
GROUP_ID = "xccdf_org.test_group_g1"
OVAL_DEF = "oval:org.test:def:1"
OVAL_DEF2 = "oval:org.test:def:2"
OVAL_HREF = "content.oval.xml"

OVAL_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
                  xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
  <generator>
    <oval:product_name>OpenSCAP identity test</oval:product_name>
    <oval:schema_version>5.10.1</oval:schema_version>
    <oval:timestamp>2026-01-01T00:00:00</oval:timestamp>
  </generator>
  <definitions>
    <definition id="{defid}" version="1" class="compliance">
      <metadata><title>t</title><description>d</description></metadata>
      <criteria><criterion test_ref="oval:org.test:tst:1" comment="c"/></criteria>
    </definition>
  </definitions>
  <tests>
    <ind:variable_test id="oval:org.test:tst:1" version="1" check="all"
                       check_existence="none_exist" comment="c">
      <ind:object object_ref="oval:org.test:obj:1"/>
    </ind:variable_test>
  </tests>
  <objects>
    <ind:variable_object id="oval:org.test:obj:1" version="1">
      <ind:var_ref>oval:org.test:var:1</ind:var_ref>
    </ind:variable_object>
  </objects>
  <variables>
    <constant_variable id="oval:org.test:var:1" version="1" datatype="string" comment="c">
      <value>present</value>
    </constant_variable>
  </variables>
</oval_definitions>
"""

def oval(defid=OVAL_DEF):
    return OVAL_TMPL.format(defid=defid)

def rule_xml(rule_id, version, title, desc, oval_name, oval_href, group):
    lines = [
        f'  <Rule id="{rule_id}" selected="true">',
        f'    <version>{version}</version>',
        f'    <title>{title}</title>',
        f'    <description>{desc}</description>',
        '    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">',
        f'      <check-content-ref href="{oval_href}" name="{oval_name}"/>',
        '    </check>',
        '  </Rule>']
    if group:
        lines = ["  " + ln for ln in lines]
        lines = [f'  <Group id="{group}">'] + lines + ['  </Group>']
    return "\n".join(lines)

def bench(rule_id=RULE_ID, version="1.0", title="Rule A title",
          desc="Rule A description", group=None, oval_name=OVAL_DEF,
          oval_href=OVAL_HREF, pretty=True):
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{BENCH_ID}">',
        '  <status>accepted</status>',
        '  <title>Identity test benchmark</title>',
        f'  <version>{version}</version>',
        rule_xml(rule_id, version, title, desc, oval_name, oval_href, group),
        '</Benchmark>']
    if pretty:
        return "\n".join(parts) + "\n"
    # serialization variant: single line, no indentation
    return "".join(l.strip() for l in parts) + "\n"

def write(d, name, text):
    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
        f.write(text)

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write(out, OVAL_HREF, oval())
    write(out, "v1.xccdf.xml", bench(pretty=True))
    write(out, "v1_compact.xccdf.xml", bench(pretty=False))
    write(out, "bodychange.xccdf.xml",
          bench(version="1.0", title="Rule A title CHANGED",
                desc="Rule A description CHANGED"))
    write(out, "versiononly.xccdf.xml", bench(version="2.0"))
    write(out, "renamed.xccdf.xml", bench(rule_id=RULE_ID_RENAMED))
    write(out, "moved.xccdf.xml", bench(group=GROUP_ID))
    write(out, "logicchange.oval.xml", oval(OVAL_DEF2))
    write(out, "logicchange.xccdf.xml",
          bench(oval_name=OVAL_DEF2, oval_href="logicchange.oval.xml"))
    print("fixtures written to", out)

if __name__ == "__main__":
    main()
