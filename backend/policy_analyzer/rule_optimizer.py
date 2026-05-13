import json
from typing import List, Dict, Set, Tuple
from .models import FirewallRule
from itertools import combinations


class RuleOptimizer:
    """
    Enterprise-grade firewall rule optimizer with:
    - Redundancy detection
    - Security gap analysis
    - Overly permissive rule detection
    - Rule consolidation suggestions
    - Compliance mapping (ISO 27001, NIST)
    - Audit report generation
    """

    def __init__(self, rules: List[FirewallRule]):
        """
        Initialize RuleOptimizer with parsed firewall rules.
        
        Args:
            rules (List[FirewallRule]): List of FirewallRule objects to analyze
        """
        self.rules = rules
        self.analysis_results = {}
        self.redundancies = []
        self.security_gaps = []
        self.overly_permissive = []
        self.optimization_suggestions = []
        self.compliance_findings = []

    def analyze_all(self) -> Dict:
        """
        Run all analysis modules and return comprehensive results.
        
        Returns:
            Dict: Complete analysis including redundancy, gaps, and suggestions
        """
        print("🔍 Starting comprehensive rule analysis...\n")
        
        self.detect_redundancies()
        self.detect_security_gaps()
        self.detect_overly_permissive_rules()
        self.suggest_rule_consolidation()
        self.check_compliance()
        
        self.analysis_results = {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules if r.enabled),
            "disabled_rules": sum(1 for r in self.rules if not r.enabled),
            "redundancies": self.redundancies,
            "security_gaps": self.security_gaps,
            "overly_permissive_rules": self.overly_permissive,
            "optimization_suggestions": self.optimization_suggestions,
            "compliance_findings": self.compliance_findings,
        }
        
        return self.analysis_results

    # ==================== REDUNDANCY DETECTION ====================
    
    def detect_redundancies(self) -> List[Dict]:
        """
        Identify redundant rules that have overlapping source/destination/service.
        A rule is redundant if another rule with same criteria and action already exists.
        
        Returns:
            List[Dict]: List of redundancy findings
        """
        print("🔍 Detecting redundant rules...")
        
        self.redundancies = []
        
        # Compare each rule pair
        for i, rule1 in enumerate(self.rules):
            for j, rule2 in enumerate(self.rules):
                if i >= j:  # Skip self-comparison and duplicates
                    continue
                
                # Check if rules are identical (same source, dest, service, action)
                if self._rules_identical(rule1, rule2):
                    redundancy = {
                        "type": "IDENTICAL",
                        "rule1": rule1.name,
                        "rule2": rule2.name,
                        "reason": f"Rules {rule1.name} and {rule2.name} have identical criteria",
                        "severity": "HIGH",
                        "recommendation": f"Remove {rule2.name} (keep {rule1.name})"
                    }
                    self.redundancies.append(redundancy)
                
                # Check if rule1 completely subsumes rule2
                elif self._rule_subsumes(rule1, rule2):
                    redundancy = {
                        "type": "SUBSUMED",
                        "rule1": rule1.name,
                        "rule2": rule2.name,
                        "reason": f"{rule1.name} makes {rule2.name} unnecessary",
                        "severity": "MEDIUM",
                        "recommendation": f"Consider removing {rule2.name}"
                    }
                    self.redundancies.append(redundancy)
        
        if self.redundancies:
            print(f"  ⚠️  Found {len(self.redundancies)} redundancy issues\n")
        else:
            print(f"  ✅ No redundancies detected\n")
        
        return self.redundancies

    def _rules_identical(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if two rules are identical."""
        return (
            rule1.source == rule2.source
            and rule1.destination == rule2.destination
            and rule1.service == rule2.service
            and rule1.action == rule2.action
        )

    def _rule_subsumes(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """
        Check if rule1 completely subsumes rule2.
        rule1 subsumes rule2 if rule1 matches everything rule2 matches.
        """
        # If actions differ, no subsumption
        if rule1.action != rule2.action:
            return False
        
        # Check if rule1's criteria are broader than rule2's
        source_subsumes = rule1.source == "any" or rule1.source == rule2.source
        dest_subsumes = rule1.destination == "any" or rule1.destination == rule2.destination
        service_subsumes = rule1.service == "any" or rule1.service == rule2.service
        
        return source_subsumes and dest_subsumes and service_subsumes

    # ==================== SECURITY GAP DETECTION ====================
    
    def detect_security_gaps(self) -> List[Dict]:
        """
        Identify potential security gaps in the rule set.
        E.g., allow rules without corresponding deny rules, missing logging.
        
        Returns:
            List[Dict]: List of security gap findings
        """
        print("🔍 Detecting security gaps...")
        
        self.security_gaps = []
        
        # Check for allow rules without corresponding deny
        allow_rules = [r for r in self.rules if r.is_allow_rule()]
        deny_rules = [r for r in self.rules if r.is_deny_rule()]
        
        if allow_rules and not deny_rules:
            gap = {
                "type": "MISSING_DENY_RULES",
                "severity": "HIGH",
                "reason": "No deny rules found. Policy should follow 'allow explicit, deny all others'",
                "recommendation": "Add explicit deny rules at the end of the policy"
            }
            self.security_gaps.append(gap)
        
        # Check for overly broad allow rules
        for rule in allow_rules:
            if rule.source == "any" and rule.destination == "any":
                gap = {
                    "type": "OVERLY_BROAD_ALLOW",
                    "rule": rule.name,
                    "severity": "CRITICAL",
                    "reason": f"Rule {rule.name} allows traffic from any to any",
                    "recommendation": "Restrict source and destination to specific networks"
                }
                self.security_gaps.append(gap)
        
        # Check for rules without descriptions
        for rule in self.rules:
            if not rule.description or rule.description == "":
                gap = {
                    "type": "MISSING_DOCUMENTATION",
                    "rule": rule.name,
                    "severity": "LOW",
                    "reason": f"Rule {rule.name} lacks business justification",
                    "recommendation": "Add descriptive text explaining business need"
                }
                self.security_gaps.append(gap)
        
        if self.security_gaps:
            print(f"  ⚠️  Found {len(self.security_gaps)} security gaps\n")
        else:
            print(f"  ✅ No critical security gaps detected\n")
        
        return self.security_gaps

    # ==================== OVERLY PERMISSIVE RULE DETECTION ====================
    
    def detect_overly_permissive_rules(self) -> List[Dict]:
        """
        Identify rules that are too permissive and pose security risks.
        
        Returns:
            List[Dict]: List of overly permissive rule findings
        """
        print("🔍 Analyzing rule permissiveness...")
        
        self.overly_permissive = []
        
        for rule in self.rules:
            if not rule.is_allow_rule():
                continue
            
            permissiveness_score = 0
            reasons = []
            
            # Score based on how broad the rule is
            if rule.source == "any":
                permissiveness_score += 3
                reasons.append("source=any (accepts all sources)")
            
            if rule.destination == "any":
                permissiveness_score += 3
                reasons.append("destination=any (targets all destinations)")
            
            if rule.service == "any":
                permissiveness_score += 2
                reasons.append("service=any (allows all services/ports)")
            
            # Flag high-permissiveness rules
            if permissiveness_score >= 5:
                severity = "CRITICAL" if permissiveness_score >= 6 else "HIGH"
                finding = {
                    "rule": rule.name,
                    "permissiveness_score": permissiveness_score,
                    "severity": severity,
                    "reasons": reasons,
                    "recommendation": "Restrict source, destination, and/or service to specific values"
                }
                self.overly_permissive.append(finding)
        
        if self.overly_permissive:
            print(f"  ⚠️  Found {len(self.overly_permissive)} overly permissive rules\n")
        else:
            print(f"  ✅ No critically permissive rules detected\n")
        
        return self.overly_permissive

    # ==================== RULE CONSOLIDATION ====================
    
    def suggest_rule_consolidation(self) -> List[Dict]:
        """
        Suggest ways to consolidate multiple rules into fewer, more efficient rules.
        
        Returns:
            List[Dict]: Consolidation suggestions
        """
        print("🔍 Analyzing consolidation opportunities...")
        
        self.optimization_suggestions = []
        
        # Find rules with same source and action, different destinations
        consolidation_map = {}
        for rule in self.rules:
            key = (rule.source, rule.action)
            if key not in consolidation_map:
                consolidation_map[key] = []
            consolidation_map[key].append(rule)
        
        # Suggest consolidation where multiple rules could be combined
        for (source, action), rules in consolidation_map.items():
            if len(rules) > 1:
                destinations = [r.destination for r in rules]
                services = [r.service for r in rules]
                
                suggestion = {
                    "type": "CONSOLIDATE_RULES",
                    "source": source,
                    "action": action,
                    "rules_to_consolidate": [r.name for r in rules],
                    "rule_count": len(rules),
                    "potential_destinations": destinations,
                    "potential_services": services,
                    "recommendation": f"Consider consolidating {len(rules)} rules with source={source} and action={action}"
                }
                self.optimization_suggestions.append(suggestion)
        
        if self.optimization_suggestions:
            print(f"  ✅ Found {len(self.optimization_suggestions)} consolidation opportunities\n")
        else:
            print(f"  ℹ️  No consolidation opportunities found\n")
        
        return self.optimization_suggestions

    # ==================== COMPLIANCE CHECKING ====================
    
    def check_compliance(self) -> List[Dict]:
        """
        Map rules to compliance frameworks (ISO 27001, NIST) and identify gaps.
        
        Returns:
            List[Dict]: Compliance mapping findings
        """
        print("🔍 Mapping to compliance frameworks...")
        
        self.compliance_findings = []
        
        # ISO 27001 controls that firewall rules support
        iso_controls = {
            "A.13.1.1": "Network perimeter segregation",
            "A.13.1.3": "Segregation of networks",
            "A.13.2.1": "Information transfer policies and procedures",
        }
        
        # NIST controls that firewall rules support
        nist_controls = {
            "SC-7": "Boundary Protection",
            "SC-7(1)": "Managed Interfaces",
            "SC-7(5)": "Deny by Default",
        }
        
        allow_rules = [r for r in self.rules if r.is_allow_rule()]
        deny_rules = [r for r in self.rules if r.is_deny_rule()]
        
        # Check for deny-by-default (NIST SC-7(5))
        if deny_rules:
            self.compliance_findings.append({
                "framework": "NIST",
                "control": "SC-7(5)",
                "status": "COMPLIANT",
                "finding": "Policy implements deny-by-default principle",
                "rules_supporting": len(deny_rules)
            })
        else:
            self.compliance_findings.append({
                "framework": "NIST",
                "control": "SC-7(5)",
                "status": "NON-COMPLIANT",
                "finding": "No deny rules detected. Implement deny-by-default",
                "recommendation": "Add deny rules to enforce deny-by-default"
            })
        
        # Check for network segregation (ISO 27001 A.13.1.3)
        if self._has_network_segregation():
            self.compliance_findings.append({
                "framework": "ISO 27001",
                "control": "A.13.1.3",
                "status": "COMPLIANT",
                "finding": "Policy includes rules supporting network segregation",
                "rules_supporting": len(allow_rules)
            })
        
        print(f"  ✅ Compliance mapping complete ({len(self.compliance_findings)} findings)\n")
        
        return self.compliance_findings

    def _has_network_segregation(self) -> bool:
        """Check if rules implement network segregation."""
        # Simple heuristic: multiple rules targeting different specific destinations
        destinations = set()
        for rule in self.rules:
            if rule.destination != "any":
                destinations.add(rule.destination)
        return len(destinations) > 1

    # ==================== REPORTING ====================
    
    def print_summary(self) -> None:
        """Print human-readable analysis summary."""
        if not self.analysis_results:
            print("⚠️  Run analyze_all() first")
            return
        
        print("\n" + "="*70)
        print("🔐 FIREWALL POLICY ANALYSIS REPORT")
        print("="*70 + "\n")
        
        # Overview
        print("📊 POLICY OVERVIEW")
        print(f"  Total Rules: {self.analysis_results['total_rules']}")
        print(f"  Enabled: {self.analysis_results['enabled_rules']}")
        print(f"  Disabled: {self.analysis_results['disabled_rules']}\n")
        
        # Redundancies
        print("🔁 REDUNDANCY ANALYSIS")
        if self.analysis_results['redundancies']:
            for i, red in enumerate(self.analysis_results['redundancies'], 1):
                print(f"  {i}. [{red['severity']}] {red['type']}")
                print(f"     Affected Rules: {red['rule1']} <→> {red['rule2']}")
                print(f"     Recommendation: {red['recommendation']}\n")
        else:
            print("  ✅ No redundancies found\n")
        
        # Security Gaps
        print("⚠️  SECURITY GAPS")
        if self.analysis_results['security_gaps']:
            for i, gap in enumerate(self.analysis_results['security_gaps'], 1):
                print(f"  {i}. [{gap['severity']}] {gap['type']}")
                if 'rule' in gap:
                    print(f"     Rule: {gap['rule']}")
                print(f"     Recommendation: {gap['recommendation']}\n")
        else:
            print("  ✅ No critical gaps found\n")
        
        # Overly Permissive
        print("🚨 PERMISSIVENESS ANALYSIS")
        if self.analysis_results['overly_permissive_rules']:
            for i, perm in enumerate(self.analysis_results['overly_permissive_rules'], 1):
                print(f"  {i}. [{perm['severity']}] {perm['rule']}")
                print(f"     Score: {perm['permissiveness_score']}/8")
                print(f"     Issues: {', '.join(perm['reasons'])}\n")
        else:
            print("  ✅ No overly permissive rules found\n")
        
        # Optimization
        print("⚡ OPTIMIZATION OPPORTUNITIES")
        if self.analysis_results['optimization_suggestions']:
            for i, opt in enumerate(self.analysis_results['optimization_suggestions'], 1):
                print(f"  {i}. Consolidate {opt['rule_count']} rules")
                print(f"     {opt['recommendation']}\n")
        else:
            print("  ℹ️  No consolidation opportunities\n")
        
        # Compliance
        print("✅ COMPLIANCE STATUS")
        for comp in self.analysis_results['compliance_findings']:
            status_icon = "✅" if comp['status'] == "COMPLIANT" else "❌"
            print(f"  {status_icon} {comp['framework']} {comp['control']}: {comp['status']}")
            print(f"     {comp['finding']}\n")
        
        print("="*70 + "\n")

    def export_json(self, filename: str = "analysis_report.json") -> None:
        """
        Export analysis results to JSON file.
        
        Args:
            filename (str): Output filename
        """
        if not self.analysis_results:
            print("⚠️  Run analyze_all() first")
            return
        
        with open(filename, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)
        
        print(f"✅ Report exported to {filename}")

    def get_risk_score(self) -> Dict:
        """
        Calculate overall risk score based on findings.
        
        Returns:
            Dict: Risk score breakdown (0-100)
        """
        risk_score = 0
        
        # Redundancy risk
        if self.redundancies:
            risk_score += min(10, len(self.redundancies) * 2)
        
        # Security gap risk
        gap_severity_weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1}
        for gap in self.security_gaps:
            risk_score += gap_severity_weights.get(gap.get("severity", "LOW"), 0)
        
        # Overly permissive risk
        for perm in self.overly_permissive:
            if perm['severity'] == "CRITICAL":
                risk_score += 15
            elif perm['severity'] == "HIGH":
                risk_score += 8
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "🔴 CRITICAL"
        elif risk_score >= 50:
            risk_level = "🟠 HIGH"
        elif risk_score >= 30:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        return {
            "score": risk_score,
            "risk_level": risk_level,
            "breakdown": {
                "redundancies": len(self.redundancies),
                "security_gaps": len(self.security_gaps),
                "overly_permissive_rules": len(self.overly_permissive)
            }
        }
