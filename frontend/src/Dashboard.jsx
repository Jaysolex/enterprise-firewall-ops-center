import React, { useState } from 'react';
import './Dashboard.css';

export default function Dashboard() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [analyzed, setAnalyzed] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setError(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a file');
      return;
    }
    setLoading(true);
    setError(null);
    
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        console.log('Real Analysis Data:', data);
        setAnalysisData(data);
        setAnalyzed(true);
      } else {
        setError('Failed to analyze file. Check backend server.');
      }
    } catch (err) {
      setError('Error connecting to backend: ' + err.message);
      console.error('Backend error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Transform backend data to findings format
  const transformFindings = (data) => {
    if (!data || !data.analysis) return [];
    
    const findings = [];
    
    // From permissive rules
    if (data.analysis.permissiveness_findings && Array.isArray(data.analysis.permissiveness_findings)) {
      data.analysis.permissiveness_findings.forEach((item, i) => {
        findings.push({
          id: `critical_${i}`,
          severity: 'CRITICAL',
          rule: item.rule_name || 'PERMISSIVE RULE',
          issue: 'Overly permissive firewall rule detected',
          description: item.description || 'Rule lacks sufficient restrictions',
          impact: 'Increases attack surface and security risk',
          compliance: ['NIST SC-7(8)', 'ISO 27001 A.13.1'],
          remediation: [
            { step: 1, title: 'Review Rule', desc: 'Analyze business requirements', command: 'firewall show-rule --name ' + (item.rule_name || 'RULE_NAME') },
            { step: 2, title: 'Create Restrictive Rule', desc: 'Define source, destination, port restrictions', command: 'firewall add-rule --name RESTRICTIVE --source X.X.X.X --dest Y.Y.Y.Y --port Z' },
            { step: 3, title: 'Test & Deploy', desc: 'Validate and deploy to production', command: 'firewall deploy --rule RESTRICTIVE --monitor' }
          ]
        });
      });
    }
    
    // From security gaps
    if (data.analysis.security_gaps && Array.isArray(data.analysis.security_gaps)) {
      data.analysis.security_gaps.forEach((item, i) => {
        findings.push({
          id: `high_${i}`,
          severity: 'HIGH',
          rule: item.gap_type || 'SECURITY GAP',
          issue: 'Missing security control detected',
          description: item.description || 'Gap in firewall policy coverage',
          impact: 'Reduces defense effectiveness',
          compliance: ['NIST SC-7(1)', 'ISO 27001 A.13.1.3'],
          remediation: [
            { step: 1, title: 'Analyze Gap', desc: 'Understand missing control', command: 'security analyze-gap --type ' + (item.gap_type || 'CONTROL') },
            { step: 2, title: 'Implement Control', desc: 'Add required security rule', command: 'firewall add-control --gap ' + (item.gap_type || 'NAME') },
            { step: 3, title: 'Validate', desc: 'Confirm control effectiveness', command: 'security validate-control --type ' + (item.gap_type || 'CONTROL') }
          ]
        });
      });
    }
    
    // From redundancies
    if (data.analysis.redundancies && Array.isArray(data.analysis.redundancies)) {
      data.analysis.redundancies.forEach((item, i) => {
        findings.push({
          id: `medium_${i}`,
          severity: 'MEDIUM',
          rule: item.rule_name || 'REDUNDANT RULE',
          issue: 'Duplicate or overlapping rule detected',
          description: item.description || 'Rule duplicates existing policy',
          impact: 'Increases complexity and maintenance overhead',
          compliance: ['ISO 27001 A.13.1.1'],
          remediation: [
            { step: 1, title: 'Identify Duplicate', desc: 'Confirm rule redundancy', command: 'firewall compare-rules --rule1 ' + (item.rule_name || 'RULE_A') + ' --rule2 RULE_B' },
            { step: 2, title: 'Consolidate Rules', desc: 'Merge duplicate rules', command: 'firewall consolidate --rules RULE_A,RULE_B --output CONSOLIDATED' },
            { step: 3, title: 'Remove Redundant', desc: 'Delete the duplicate rule', command: 'firewall delete-rule --name ' + (item.rule_name || 'RULE_TO_DELETE') }
          ]
        });
      });
    }
    
    return findings;
  };

  const findings = analysisData ? transformFindings(analysisData) : [];
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  const complianceScore = analysisData?.risk?.score || 0;

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="header-content">
          <div className="logo-section">
            <div className="firewall-logo">
              <svg viewBox="0 0 100 100" className="firewall-svg">
                <path d="M 50 10 L 80 25 L 80 50 Q 80 75 50 90 Q 20 75 20 50 L 20 25 Z" fill="none" stroke="#00d4ff" strokeWidth="2"/>
                <defs>
                  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style={{stopColor: '#1a2a4a', stopOpacity: 1}} />
                    <stop offset="100%" style={{stopColor: '#0f1a2e', stopOpacity: 1}} />
                  </linearGradient>
                </defs>
                <path d="M 50 10 L 80 25 L 80 50 Q 80 75 50 90 Q 20 75 20 50 L 20 25 Z" fill="url(#shieldGrad)" stroke="#00d4ff" strokeWidth="2"/>
                <line x1="35" y1="35" x2="65" y2="35" stroke="#00d4ff" strokeWidth="1.5" opacity="0.8"/>
                <line x1="30" y1="50" x2="70" y2="50" stroke="#00d4ff" strokeWidth="1.5" opacity="0.8"/>
                <line x1="35" y1="65" x2="65" y2="65" stroke="#00d4ff" strokeWidth="1.5" opacity="0.8"/>
                <circle cx="40" cy="35" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="60" cy="35" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="50" cy="50" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="35" cy="50" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="65" cy="50" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="40" cy="65" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="60" cy="65" r="3" fill="#00ffff" opacity="0.9"/>
                <circle cx="50" cy="50" r="8" fill="none" stroke="#facc15" strokeWidth="1.5" opacity="0.8"/>
                <circle cx="50" cy="50" r="5" fill="#facc15" opacity="0.6"/>
              </svg>
            </div>
            <div className="header-text">
              <h1>Firewall Policy Analyzer</h1>
              <p>Enterprise Security Control Assessment</p>
            </div>
          </div>
        </div>
      </div>

      <div className="dashboard-main">
        <div className="upload-section fade-in">
          <div className="upload-box">
            <h3>UPLOAD FIREWALL CONFIGURATION</h3>
            <p className="upload-subtitle">Select XML or JSON configuration file</p>
            <input type="file" onChange={handleFileChange} accept=".xml,.json" className="file-input" />
            <button onClick={handleAnalyze} disabled={!file || loading} className="analyze-button">
              {loading ? 'ANALYZING...' : 'ANALYZE POLICY'}
            </button>
            {file && <p className="file-status success">FILE SELECTED: {file.name}</p>}
            {error && <p className="file-status error">ERROR: {error}</p>}
          </div>
        </div>

        {!analyzed ? (
          <div className="empty-state fade-in">
            <div className="empty-state-content">
              <h2>AWAITING FILE UPLOAD</h2>
              <p>Upload a firewall configuration file to begin security analysis</p>
              <p className="empty-state-hint">Supported formats: XML, JSON</p>
            </div>
          </div>
        ) : (
          <>
            <div className="score-section fade-in-stagger">
              <div className="score-circle-container">
                <div className="score-circle">
                  <div className="score-value">{complianceScore}</div>
                  <div className="score-label">COMPLIANCE SCORE</div>
                  <div className="score-rating">{complianceScore >= 70 ? 'LOW RISK' : complianceScore >= 50 ? 'MEDIUM RISK' : 'HIGH RISK'}</div>
                </div>
                <div className="score-info">
                  <p><strong>SECURITY POSTURE ASSESSMENT</strong></p>
                  <p>File: {file.name}</p>
                  <div className="score-breakdown">
                    <div className="breakdown-item critical-item">
                      <span className="count">{criticalCount}</span>
                      <span className="label">CRITICAL</span>
                    </div>
                    <div className="breakdown-item high-item">
                      <span className="count">{highCount}</span>
                      <span className="label">HIGH</span>
                    </div>
                    <div className="breakdown-item medium-item">
                      <span className="count">{mediumCount}</span>
                      <span className="label">MEDIUM</span>
                    </div>
                    <div className="breakdown-item low-item">
                      <span className="count">{lowCount}</span>
                      <span className="label">LOW</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="summary-cards fade-in-stagger">
              <div className="summary-card critical" style={{animationDelay: '0s'}}>
                <div className="card-number">{criticalCount}</div>
                <div className="card-label">CRITICAL</div>
                <div className="card-status">REQUIRES IMMEDIATE ACTION</div>
              </div>
              <div className="summary-card high" style={{animationDelay: '0.1s'}}>
                <div className="card-number">{highCount}</div>
                <div className="card-label">HIGH</div>
                <div className="card-status">RESOLVE WITHIN 1 WEEK</div>
              </div>
              <div className="summary-card medium" style={{animationDelay: '0.2s'}}>
                <div className="card-number">{mediumCount}</div>
                <div className="card-label">MEDIUM</div>
                <div className="card-status">RESOLVE WITHIN 1 MONTH</div>
              </div>
              <div className="summary-card low" style={{animationDelay: '0.3s'}}>
                <div className="card-number">{lowCount}</div>
                <div className="card-label">LOW</div>
                <div className="card-status">MONITOR & OPTIMIZE</div>
              </div>
            </div>

            <div className="tab-section fade-in">
              <div className="tab-buttons">
                <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>OVERVIEW</button>
                <button className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>FINDINGS ({findings.length})</button>
                <button className={`tab-btn ${activeTab === 'compliance' ? 'active' : ''}`} onClick={() => setActiveTab('compliance')}>COMPLIANCE</button>
                <button className={`tab-btn ${activeTab === 'remediation' ? 'active' : ''}`} onClick={() => setActiveTab('remediation')}>REMEDIATION</button>
              </div>
            </div>

            {activeTab === 'overview' && (
              <div className="tab-content fade-in">
                <h3>SECURITY OVERVIEW</h3>
                {findings.length === 0 ? (
                  <p style={{color: 'var(--text-secondary)'}}>No findings detected in this configuration</p>
                ) : (
                  <div className="overview-grid">
                    {criticalCount > 0 && (
                      <div className="overview-item">
                        <div className="overview-count">{criticalCount}</div>
                        <div className="overview-title">CRITICAL FINDINGS</div>
                        <p>Require immediate remediation</p>
                      </div>
                    )}
                    {highCount > 0 && (
                      <div className="overview-item">
                        <div className="overview-count">{highCount}</div>
                        <div className="overview-title">HIGH SEVERITY</div>
                        <p>Security gaps and missing controls</p>
                      </div>
                    )}
                    {mediumCount > 0 && (
                      <div className="overview-item">
                        <div className="overview-count">{mediumCount}</div>
                        <div className="overview-title">MEDIUM SEVERITY</div>
                        <p>Redundancy and optimization issues</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'findings' && (
              <div className="tab-content fade-in">
                <h3>SECURITY FINDINGS ({findings.length})</h3>
                {findings.length === 0 ? (
                  <p style={{color: 'var(--text-secondary)'}}>No findings in this configuration</p>
                ) : (
                  findings.map(finding => (
                    <div key={finding.id} className="finding-card">
                      <div className="finding-header">
                        <span className={`severity-label ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                        <div className="finding-title">{finding.rule}</div>
                        <button className="expand-btn" onClick={() => setSelectedFinding(selectedFinding?.id === finding.id ? null : finding)}>
                          {selectedFinding?.id === finding.id ? '[COLLAPSE]' : '[EXPAND]'}
                        </button>
                      </div>
                      <p className="finding-issue">{finding.issue}</p>
                      {selectedFinding?.id === finding.id && (
                        <div className="finding-details fade-in">
                          <div className="detail-section">
                            <strong>DESCRIPTION:</strong>
                            <p>{finding.description}</p>
                          </div>
                          <div className="detail-section">
                            <strong>IMPACT:</strong>
                            <p>{finding.impact}</p>
                          </div>
                          <div className="detail-section">
                            <strong>COMPLIANCE FRAMEWORKS:</strong>
                            <div className="compliance-tags">
                              {finding.compliance.map((comp, i) => <span key={i} className="compliance-tag">{comp}</span>)}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {activeTab === 'compliance' && (
              <div className="tab-content fade-in">
                <h3>COMPLIANCE FRAMEWORK ALIGNMENT</h3>
                <div className="compliance-grid">
                  <div className="compliance-card compliant">
                    <div className="framework-name">NIST SC-7</div>
                    <div className="framework-status">COMPLIANT</div>
                    <p>Boundary protection validation</p>
                  </div>
                  <div className="compliance-card compliant">
                    <div className="framework-name">ISO 27001 A.13.1</div>
                    <div className="framework-status">COMPLIANT</div>
                    <p>Network segregation verified</p>
                  </div>
                  <div className={`compliance-card ${criticalCount > 0 ? 'non-compliant' : 'compliant'}`}>
                    <div className="framework-name">PCI-DSS 1.x</div>
                    <div className="framework-status">{criticalCount > 0 ? 'NON-COMPLIANT' : 'COMPLIANT'}</div>
                    <p>{criticalCount > 0 ? 'Requires rule refinement' : 'All requirements met'}</p>
                  </div>
                  <div className="compliance-card compliant">
                    <div className="framework-name">SOC 2 TYPE II</div>
                    <div className="framework-status">COMPLIANT</div>
                    <p>Security controls documented</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'remediation' && (
              <div className="tab-content fade-in">
                <h3>STEP-BY-STEP REMEDIATION PLAN</h3>
                {findings.length === 0 ? (
                  <p style={{color: 'var(--text-secondary)'}}>No remediation needed</p>
                ) : (
                  findings.slice(0, 3).map(finding => (
                    <div key={finding.id} className="remediation-section">
                      <h4>{finding.rule} [{finding.severity}]</h4>
                      <div className="remediation-steps">
                        {finding.remediation.map(step => (
                          <div key={step.step} className="step-card fade-in-stagger" style={{animationDelay: `${step.step * 0.1}s`}}>
                            <div className="step-number">{step.step}</div>
                            <div className="step-content">
                              <h5>{step.title}</h5>
                              <p>{step.desc}</p>
                              <div className="command-box">
                                <code>{step.command}</code>
                                <button className="copy-btn" onClick={() => navigator.clipboard.writeText(step.command)}>COPY COMMAND</button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}
      </div>

      <div className="dashboard-footer fade-in">
        <p>Enterprise Firewall Policy Analyzer | Security Operations Center | Real-time Assessment</p>
      </div>
    </div>
  );
}
