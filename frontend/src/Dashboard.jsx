import React, { useState } from 'react';
import './Dashboard.css';

const Dashboard = () => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && ['xml', 'json'].includes(selectedFile.name.split('.').pop().toLowerCase())) {
      setFile(selectedFile);
      setError(null);
    } else {
      setError('Please select a valid XML or JSON file');
      setFile(null);
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a file');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Analysis failed');
      }

      setAnalysis(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 70) return '#d32f2f';
    if (score >= 50) return '#f57c00';
    if (score >= 30) return '#fbc02d';
    return '#388e3c';
  };

  const renderOverview = () => {
    if (!analysis) return null;
    const { analysis: analysisData, risk } = analysis;

    // FIX: Access compliance_findings correctly
    const complianceFindings = analysisData.compliance_findings || [];

    return (
      <div className="overview">
        <div className="risk-card">
          <h3>Risk Score</h3>
          <div className="risk-circle" style={{ backgroundColor: getRiskColor(risk.score) }}>
            <span className="risk-number">{risk.score}</span>
            <span className="risk-max">/100</span>
          </div>
          <p className="risk-level">{risk.level}</p>
        </div>

        <div className="stats-grid">
          <div className="stat-card">
            <h4>Total Rules</h4>
            <p className="stat-value">{analysisData.total_rules}</p>
          </div>

          <div className="stat-card warning">
            <h4>Redundancies</h4>
            <p className="stat-value">{analysisData.redundancies.count}</p>
          </div>

          <div className="stat-card danger">
            <h4>Security Gaps</h4>
            <p className="stat-value">{analysisData.security_gaps.count}</p>
          </div>

          <div className="stat-card warning">
            <h4>Permissive Rules</h4>
            <p className="stat-value">{analysisData.overly_permissive_rules.count}</p>
          </div>
        </div>

        <div className="compliance-section">
          <h3>✅ COMPLIANCE STATUS</h3>
          {complianceFindings && complianceFindings.length > 0 ? (
            <div className="compliance-findings">
              {complianceFindings.map((finding, idx) => (
                <div key={idx} className="compliance-card">
                  <h4>{finding.framework} {finding.control}</h4>
                  <p className="status">{finding.status}</p>
                  <p className="finding">{finding.finding}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="no-findings">No compliance findings</p>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="dashboard">
      <header className="header">
        <h1>🔐 Firewall Policy Optimizer</h1>
        <p>Enterprise-grade security analysis platform</p>
      </header>

      <div className="container">
        <section className="upload-section">
          <div className="upload-card">
            <h2>Upload Configuration</h2>
            <p>Supported formats: XML (Palo Alto), JSON</p>

            <div className="file-input-wrapper">
              <input type="file" id="file-input" onChange={handleFileChange} accept=".xml,.json" disabled={loading} />
              <label htmlFor="file-input" className="file-label">
                {file ? `📄 ${file.name}` : '📁 Choose file or drag here'}
              </label>
            </div>

            <button className="btn btn-primary" onClick={handleAnalyze} disabled={!file || loading}>
              {loading ? '🔄 Analyzing...' : '▶️ Analyze Policy'}
            </button>

            {error && <div className="error-message">❌ {error}</div>}
          </div>
        </section>

        {analysis && (
          <section className="results-section">
            <div className="results-header">
              <h2>📊 Analysis Results</h2>
            </div>

            <div className="tabs">
              <button className={`tab ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
                Overview
              </button>
            </div>

            <div className="tab-content">
              {activeTab === 'overview' && renderOverview()}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
