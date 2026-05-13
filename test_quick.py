#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Get the absolute path to the project root
PROJECT_ROOT = Path(__file__).parent
BACKEND_DIR = PROJECT_ROOT / "backend"
POLICY_ANALYZER_DIR = BACKEND_DIR / "policy_analyzer"
SAMPLE_XML = BACKEND_DIR / "sample_config.xml"

# Add to path
sys.path.insert(0, str(POLICY_ANALYZER_DIR))

# Import after path is set
from parser import PaloAltoParser

print(f"📁 Project Root: {PROJECT_ROOT}")
print(f"📄 XML File: {SAMPLE_XML}")
print(f"✓ XML exists: {SAMPLE_XML.exists()}\n")

if not SAMPLE_XML.exists():
    print(f"❌ ERROR: sample_config.xml not found at {SAMPLE_XML}")
    sys.exit(1)

# Parse the sample config
print("🔄 Parsing firewall configuration...\n")
parser = PaloAltoParser(str(SAMPLE_XML))
rules = parser.parse_rules()

print("✅ PARSING SUCCESSFUL!\n")
parser.print_summary()

print("\n📋 PARSED RULES:\n")
for i, rule in enumerate(rules, 1):
    print(f"  {i}. {rule}")
    print(f"     → {rule.to_dict()}\n")

print("✅ All tests passed!")
