import React from "react";

const DETECTION_KEYS = [
  { key: "passwords", label: "Passwords" },
  { key: "weak_passwords", label: "Weak Passwords" },
  { key: "emails", label: "Emails" },
  { key: "api_keys", label: "API Keys" },
  { key: "credit_cards", label: "Credit Cards" },
  { key: "phones", label: "Phone Numbers" },
  { key: "ips", label: "IP Addresses" },
  { key: "stack_traces", label: "Stack Traces" },
  { key: "debug_leaks", label: "Debug Leaks" },
];

const InfoPanel = ({ result }) => {
  const counts = result?.counts ?? result?.risk_result?.counts;
  const action = result?.action;
  const policies = result?.policies;

  return (
    <div className="info-panel">
      {/* Supported Inputs */}
      <div className="info-group">
        <div className="info-group-title">Supported File Formats</div>
        <div className="info-chips">
          <span className="info-chip">.txt</span>
          <span className="info-chip">.log</span>
          <span className="info-chip">.json</span>
          <span className="info-chip">.pdf</span>
          <span className="info-chip">.doc</span>
          <span className="info-chip">.docx</span>
        </div>
      </div>

      {/* Text Input Types */}
      <div className="info-group">
        <div className="info-group-title">Text Input Types</div>
        <div className="info-chips">
          <span className="info-chip">Server Logs</span>
          <span className="info-chip">Config Files</span>
          <span className="info-chip">Credentials</span>
          <span className="info-chip">API Data</span>
        </div>
      </div>

      {/* Scoring Criteria */}
      <div className="info-group">
        <div className="info-group-title">Scoring Criteria</div>
        <ul className="info-list">
          <li><span className="label">Weak Password</span><span className="value">+6</span></li>
          <li><span className="label">Strong Password</span><span className="value">+3</span></li>
          <li><span className="label">API Key / Secret</span><span className="value">+6</span></li>
          <li><span className="label">Credit Card</span><span className="value">+6</span></li>
          <li><span className="label">Email</span><span className="value">+2</span></li>
          <li><span className="label">Phone Number</span><span className="value">+2</span></li>
          <li><span className="label">IP Address</span><span className="value">+1</span></li>
          <li><span className="label">Stack Trace</span><span className="value">+2</span></li>
          <li><span className="label">Debug Leak</span><span className="value">+1</span></li>
        </ul>
      </div>

      {/* Risk Levels */}
      <div className="info-group">
        <div className="info-group-title">Risk Levels</div>
        <div className="risk-level-indicator">
          <div className="risk-level-bar level-low">LOW<br />0–2</div>
          <div className="risk-level-bar level-medium">MED<br />3–7</div>
          <div className="risk-level-bar level-high">HIGH<br />8–10</div>
        </div>
      </div>

      {/* Active Policies */}
      {policies && (
        <div className="info-group">
          <div className="info-group-title">Active Policies</div>
          <div className="policy-badges">
            <span className={`policy-badge ${policies.mask ? "on" : "off"}`}>
              {policies.mask ? "✓" : "✗"} Masking
            </span>
            <span className={`policy-badge ${policies.block_high_risk ? "on" : "off"}`}>
              {policies.block_high_risk ? "✓" : "✗"} Block High Risk
            </span>
            <span className={`policy-badge ${policies.log_analysis ? "on" : "off"}`}>
              {policies.log_analysis ? "✓" : "✗"} Log Analysis
            </span>
          </div>
        </div>
      )}

      {/* Action Status */}
      {action && (
        <div className="info-group">
          <div className="info-group-title">Action</div>
          <div className={`action-badge action-${action}`}>
            {action === "blocked" && "🚫 BLOCKED"}
            {action === "review_required" && "⚠️ REVIEW REQUIRED"}
            {action === "caution" && "⚡ CAUTION"}
            {action === "allowed" && "✅ ALLOWED"}
          </div>
        </div>
      )}

      {/* Detection Summary */}
      {counts && (
        <div className="info-group">
          <div className="info-group-title">Detection Summary</div>
          <div className="detection-summary">
            {DETECTION_KEYS.map(({ key, label }) => (
              <div key={key} className="detection-row">
                <span className="det-label">{label}</span>
                <span className={`det-count ${(counts[key] || 0) > 0 ? "has-items" : ""}`}>
                  {counts[key] || 0}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default InfoPanel;
