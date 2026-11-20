#!/usr/bin/env python3
"""Derive mutated result artifacts from one generated scan result.

All mutations are pure XML edits of the result document; no target is
rescanned.  Run with: python3 -I make_mutants.py <base_result> <out_dir>

Produces:
  targetflip.xml      - content identity untouched, rule outcome flipped
  legacy.xml          - xccdf:metadata (cid block) removed
  othertarget.xml     - target name changed, identity kept
  tailormismatch.xml  - tailoring block with a wrong benchmark-digest
  contentflip.xml     - used when the caller supplies a logic-changed base;
                        here it only flips the outcome
"""
import os
import sys
import re
import xml.etree.ElementTree as ET

CID_NS = "https://open-scap.org/ns/content-identity/1.0"
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"


def lname(tag):
    return tag.split("}", 1)[-1] if isinstance(tag, str) else "?"


def main():
    base, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    tree = ET.parse(base)
    root = tree.getroot()

    def find_test_result():
        for el in root.iter():
            if lname(el.tag) == "TestResult":
                return el
        raise SystemExit("no TestResult found")

    tr = find_test_result()

    # 1. target flip: flip the first rule-result outcome, keep identity
    t1 = ET.parse(base)
    r1 = next(el for el in t1.iter() if lname(el.tag) == "TestResult")
    for rr in r1:
        if lname(rr.tag) == "rule-result":
            for child in rr:
                if lname(child.tag) == "result" and child.text:
                    child.text = "pass" if child.text.strip() == "fail" else "fail"
            break
    t1.write(os.path.join(out, "targetflip.xml"), xml_declaration=True, encoding="UTF-8")

    # 2. legacy: strip every metadata element
    t2 = ET.parse(base)
    r2 = next(el for el in t2.iter() if lname(el.tag) == "TestResult")
    for parent in t2.iter():
        for child in list(parent):
            if lname(child.tag) == "metadata":
                parent.remove(child)
    t2.write(os.path.join(out, "legacy.xml"), xml_declaration=True, encoding="UTF-8")

    # 3. other target name
    t3 = ET.parse(base)
    r3 = next(el for el in t3.iter() if lname(el.tag) == "TestResult")
    for el in r3:
        if lname(el.tag) == "target":
            el.text = "different-machine.example.com"
            break
    t3.write(os.path.join(out, "othertarget.xml"), xml_declaration=True, encoding="UTF-8")

    # 4. tailoring mismatch: inject a cid:tailoring with a bogus benchmark digest
    raw = open(base, encoding="utf-8").read()
    m = re.search(r'content-type="xccdf" digest="([0-9a-f]+)"', raw)
    real = m.group(1) if m else "f" * 64
    fake = "0" * 64
    tail = (
        '<cid:tailoring origin="tail.xml" digest="' + ("1" * 64) +
        '" profile-id="x" benchmark-digest="' + fake + '"></cid:tailoring>'
    )
    injected = raw.replace("</cid:rules>", "</cid:rules>" + tail, 1)
    with open(os.path.join(out, "tailormismatch.xml"), "w", encoding="utf-8") as f:
        f.write(injected)

    print("mutants written to", out, "real xccdf digest:", real)


if __name__ == "__main__":
    main()
