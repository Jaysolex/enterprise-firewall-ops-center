"""Enterprise Firewall Policy Optimizer - REST API"""
import json, os
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys

PROJECT_ROOT = Path(__file__).parent.parent
POLICY_ANALYZER_DIR = PROJECT_ROOT / "policy_analyzer"
sys.path.insert(0, str(POLICY_ANALYZER_DIR))

from policy_analyzer.parser import PaloAltoParser, JSONConfigParser
from policy_analyzer.rule_optimizer import RuleOptimizer

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = str(PROJECT_ROOT / 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
CORS(app)

latest_analysis = {"timestamp": None, "results": None, "filename": None}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'xml', 'json'}

def parse_config_file(filepath):
    filepath_obj = Path(filepath)
    if filepath_obj.suffix.lower() == '.xml':
        parser = PaloAltoParser(filepath)
    elif filepath_obj.suffix.lower() == '.json':
        parser = JSONConfigParser(filepath)
    else:
        raise ValueError(f"Unsupported: {filepath_obj.suffix}")
    return parser.parse_rules(), parser

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "Firewall Optimizer", "version": "1.0.0", "timestamp": datetime.now().isoformat()}), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Empty filename"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid format"}), 400
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        try:
            rules, parser = parse_config_file(filepath)
        except Exception as e:
            return jsonify({"error": "Parse error", "message": str(e)}), 400
        optimizer = RuleOptimizer(rules)
        analysis_results = optimizer.analyze_all()
        risk_score = optimizer.get_risk_score()
        response_data = {
            "status": "success",
            "file": filename,
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis_results,
            "risk": {"score": risk_score['score'], "level": risk_score['risk_level'], "breakdown": risk_score['breakdown']}
        }
        latest_analysis['timestamp'] = datetime.now().isoformat()
        latest_analysis['results'] = response_data
        latest_analysis['filename'] = filename
        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": "Server error", "message": str(e)}), 500

@app.route('/api/report', methods=['GET'])
def get_report():
    if latest_analysis['results'] is None:
        return jsonify({"error": "No analysis available"}), 404
    return jsonify(latest_analysis['results']), 200

@app.route('/api/risk-score', methods=['GET'])
def get_risk_score():
    if latest_analysis['results'] is None:
        return jsonify({"error": "No analysis available"}), 404
    return jsonify(latest_analysis['results']['risk']), 200

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 Firewall Policy Optimizer - REST API")
    print("="*70)
    print("\nAvailable endpoints:")
    print("  POST  /api/analyze - Upload config file")
    print("  GET   /api/report - Get latest report")
    print("  GET   /api/risk-score - Get risk score")
    print("  GET   /api/health - Health check\n")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)
