#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import xml.etree.ElementTree as ET
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

def analyze_xml_firewall(root, findings):
    """Analyze XML firewall configuration - PERFECT LOGIC"""
    rules = root.findall('.//rule')
    findings['total_rules'] = len(rules)
    rule_patterns = {}
    
    for idx, rule in enumerate(rules):
        rule_name_elem = rule.find('name')
        rule_name = rule_name_elem.text if rule_name_elem is not None else f'RULE_{idx}'
        
        source_elem = rule.find('source')
        dest_elem = rule.find('destination')
        action_elem = rule.find('action')
        port_elem = rule.find('port')
        state_elem = rule.find('state')
        
        source = source_elem.text.lower() if source_elem is not None and source_elem.text else 'any'
        destination = dest_elem.text.lower() if dest_elem is not None and dest_elem.text else 'any'
        action = action_elem.text.upper() if action_elem is not None and action_elem.text else 'ALLOW'
        state = state_elem.text.upper() if state_elem is not None and state_elem.text else None
        
        # SKIP DENY rules - they are GOOD for security!
        if action == 'DENY':
            continue
        
        # SKIP stateful/established connections - they are SAFE!
        if state and 'ESTABLISHED' in state:
            continue
        
        # Check for critical permissiveness (allow ANY-to-ANY without port restriction)
        is_any_source = 'any' in source or 'all' in source or '*' in source or '0.0.0.0/0' in source
        is_any_dest = 'any' in destination or 'all' in destination or '*' in destination or '0.0.0.0/0' in destination
        
        if is_any_source and is_any_dest and action == 'ALLOW' and port_elem is None:
            findings['permissiveness_findings'].append({
                'rule_name': rule_name,
                'description': f'Rule {rule_name} allows unrestricted traffic without port specification',
                'severity': 'CRITICAL'
            })
        
        # Check for missing port restrictions ONLY on ALLOW rules with broad scope
        if action == 'ALLOW' and (is_any_source or is_any_dest) and port_elem is None:
            findings['security_gaps'].append({
                'gap_type': 'MISSING_PORT_RESTRICTION',
                'description': f'Rule {rule_name} lacks port restrictions with broad scope',
                'severity': 'HIGH'
            })
        
        # Only flag as redundant if source, destination, AND port are identical
        if action == 'ALLOW':
            port_text = port_elem.text if port_elem is not None else 'NO_PORT'
            protocol = rule.find('protocol')
            protocol_text = protocol.text if protocol is not None else 'ANY'
            pattern = f"{source}->{destination}:{protocol_text}:{port_text}"
            if pattern in rule_patterns:
                findings['redundancies'].append({
                    'rule_name': rule_name,
                    'description': f'Exact duplicate ALLOW pattern (same source, destination, protocol, and port)',
                    'severity': 'MEDIUM'
                })
            else:
                rule_patterns[pattern] = True

def analyze_json_firewall(data, findings):
    """Analyze JSON firewall configuration - PERFECT LOGIC"""
    rules = data.get('rules', [])
    findings['total_rules'] = len(rules)
    rule_patterns = {}
    
    for idx, rule in enumerate(rules):
        rule_name = rule.get('name', f'RULE_{idx}')
        source = str(rule.get('source', 'any')).lower()
        destination = str(rule.get('destination', 'any')).lower()
        action = str(rule.get('action', 'ALLOW')).upper()
        state = str(rule.get('state', '')).upper()
        
        # SKIP DENY rules - they are GOOD!
        if action == 'DENY':
            continue
        
        # SKIP established connections - they are SAFE!
        if 'ESTABLISHED' in state:
            continue
        
        # Critical: ANY to ANY without port
        is_any_source = 'any' in source or 'all' in source or '*' in source or '0.0.0.0/0' in source
        is_any_dest = 'any' in destination or 'all' in destination or '*' in destination or '0.0.0.0/0' in destination
        
        if is_any_source and is_any_dest and action == 'ALLOW' and 'port' not in rule:
            findings['permissiveness_findings'].append({
                'rule_name': rule_name,
                'description': f'Rule {rule_name} permits unrestricted traffic flow',
                'severity': 'CRITICAL'
            })
        
        # High: Missing port restrictions with broad scope
        if action == 'ALLOW' and (is_any_source or is_any_dest) and 'port' not in rule:
            findings['security_gaps'].append({
                'gap_type': 'MISSING_PORT_RESTRICTION',
                'description': f'Rule {rule_name} lacks port restrictions with broad scope',
                'severity': 'HIGH'
            })
        
        # Only flag as redundant if source, destination, protocol, AND port match
        if action == 'ALLOW':
            port_text = str(rule.get('port', 'NO_PORT'))
            protocol_text = str(rule.get('protocol', 'ANY')).upper()
            pattern = f"{source}->{destination}:{protocol_text}:{port_text}"
            if pattern in rule_patterns:
                findings['redundancies'].append({
                    'rule_name': rule_name,
                    'description': 'Exact duplicate ALLOW pattern (same source, destination, protocol, and port)',
                    'severity': 'MEDIUM'
                })
            else:
                rule_patterns[pattern] = True

def analyze_firewall_config(file_content, filename):
    """Analyze firewall configuration - REAL analysis based on file content"""
    findings = {
        'permissiveness_findings': [],
        'security_gaps': [],
        'redundancies': [],
        'total_rules': 0
    }
    
    try:
        if filename.endswith('.xml'):
            root = ET.fromstring(file_content)
            analyze_xml_firewall(root, findings)
        elif filename.endswith('.json'):
            data = json.loads(file_content)
            analyze_json_firewall(data, findings)
        else:
            return None
        
        critical = len(findings['permissiveness_findings'])
        high = len(findings['security_gaps'])
        medium = len(findings['redundancies'])
        
        risk_score = max(0, 100 - (critical * 15 + high * 10 + medium * 5))
        risk_level = 'LOW' if risk_score >= 70 else 'MEDIUM' if risk_score >= 50 else 'HIGH'
        
        return {
            'analysis': findings,
            'risk': {
                'score': risk_score,
                'level': risk_level,
                'critical': critical,
                'high': high,
                'medium': medium
            },
            'timestamp': datetime.now().isoformat(),
            'filename': filename
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'service': 'Firewall Optimizer',
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        try:
            content = file.read().decode('utf-8')
        except UnicodeDecodeError:
            return jsonify({'error': 'File must be valid UTF-8'}), 400
        
        if not content:
            return jsonify({'error': 'File is empty'}), 400
        
        result = analyze_firewall_config(content, file.filename)
        
        if result is None:
            return jsonify({'error': 'Unsupported file format. Use .xml or .json'}), 400
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/report', methods=['GET'])
def report():
    return jsonify({'message': 'Upload a file to /api/analyze'}), 200

if __name__ == '__main__':
    print("=" * 60)
    print("🔥 FIREWALL POLICY ANALYZER BACKEND")
    print("=" * 60)
    print("✅ PERFECT Analysis (checks protocol + port)")
    print("✅ Flask running on http://localhost:5000")
    print("📤 POST /api/analyze - Analyze firewall config")
    print("💚 GET /api/health - Health check")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
