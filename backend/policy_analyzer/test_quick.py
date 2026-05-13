#!/usr/bin/env python3
import sys
sys.path.insert(0, 'backend/policy_analyzer')

from parser import PaloAltoParser

# Parse the sample config
parser = PaloAltoParser("backend/sample_config.xml")
rules = parser.parse_rules()

print("\n✅ PARSING SUCCESSFUL!\n")
parser.print_summary()

print("\n📋 PARSED RULES:\n")
for rule in rules:
    print(f"  {rule}")
    print(f"    → {rule.to_dict()}\n")
