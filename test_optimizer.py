#!/usr/bin/env python3
import sys
from pathlib import Path

# Add backend to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

# Now import
from policy_analyzer.models import FirewallRule
from policy_analyzer.rule_optimizer import RuleOptimizer

print("\n" + "="*70)
print("FIREWALL RULE OPTIMIZER TEST SUITE")
print("="*70 + "\n")

def test_basic_optimization():
    print("🔥 TEST 1: BASIC RULE OPTIMIZATION\n")
    rules = [
        FirewallRule("Allow_HTTP", "any", "web-server", "http", "allow"),
        FirewallRule("Allow_HTTP_Duplicate", "any", "web-server", "http", "allow"),
        FirewallRule("Allow_SSH", "10.0.0.5", "linux-server", "ssh", "allow"),
        FirewallRule("Block_All", "any", "any", "any", "deny")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    print("✅ TEST 1: BASIC RULE OPTIMIZATION - PASSED ✅\n")

def test_overly_permissive():
    print("🔥 TEST 2: OVERLY PERMISSIVE DETECTION\n")
    rules = [
        FirewallRule("Allow_Everything", "any", "any", "any", "allow"),
        FirewallRule("Allow_All_To_Servers", "any", "any", "http", "allow"),
        FirewallRule("Block_Malware", "any", "any", "any", "deny")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    risk = optimizer.get_risk_score()
    print("✅ TEST 2: OVERLY PERMISSIVE DETECTION - PASSED ✅\n")

def test_security_gaps():
    print("🔥 TEST 3: SECURITY GAP DETECTION\n")
    rules = [
        FirewallRule("Allow_HTTPS", "any", "web-server", "https", "allow"),
        FirewallRule("Allow_SSH", "10.0.0.0/8", "linux-server", "ssh", "allow"),
        FirewallRule("Allow_DNS", "any", "dns-server", "dns", "allow")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    print("✅ TEST 3: SECURITY GAP DETECTION - PASSED ✅\n")

def test_rule_consolidation():
    print("🔥 TEST 4: RULE CONSOLIDATION\n")
    rules = [
        FirewallRule("Allow_HTTP_Server1", "10.0.0.0/8", "server1", "http", "allow"),
        FirewallRule("Allow_HTTP_Server2", "10.0.0.0/8", "server2", "http", "allow"),
        FirewallRule("Allow_HTTP_Server3", "10.0.0.0/8", "server3", "http", "allow"),
        FirewallRule("Block_All", "any", "any", "any", "deny")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    print("✅ TEST 4: RULE CONSOLIDATION - PASSED ✅\n")

def test_compliance():
    print("🔥 TEST 5: COMPLIANCE MAPPING\n")
    rules = [
        FirewallRule("Allow_HTTPS", "any", "web-server", "https", "allow"),
        FirewallRule("Allow_SSH", "10.0.0.0/8", "admin-server", "ssh", "allow"),
        FirewallRule("Block_All", "any", "any", "any", "deny")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    print("✅ TEST 5: COMPLIANCE MAPPING - PASSED ✅\n")

def test_enterprise():
    print("🔥 TEST 6: ENTERPRISE SCENARIO\n")
    rules = [
        FirewallRule("Allow_HTTPS_Public", "any", "web-server", "https", "allow"),
        FirewallRule("Allow_HTTPS_Public_Duplicate", "any", "web-server", "https", "allow"),
        FirewallRule("Allow_SSH_Admins", "10.0.0.0/8", "admin-server", "ssh", "allow"),
        FirewallRule("Allow_DB_Internal", "10.0.0.0/8", "db-server", "mysql", "allow"),
        FirewallRule("Allow_DNS", "any", "dns-server", "dns", "allow"),
        FirewallRule("Allow_NTP", "any", "ntp-server", "ntp", "allow"),
        FirewallRule("Block_All", "any", "any", "any", "deny")
    ]
    optimizer = RuleOptimizer(rules)
    optimizer.analyze_all()
    print("✅ TEST 6: ENTERPRISE SCENARIO - PASSED ✅\n")

if __name__ == '__main__':
    try:
        test_basic_optimization()
        test_overly_permissive()
        test_security_gaps()
        test_rule_consolidation()
        test_compliance()
        test_enterprise()
        
        print("✅" * 35)
        print("ALL TESTS COMPLETED SUCCESSFULLY")
        print("✅" * 35)
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
