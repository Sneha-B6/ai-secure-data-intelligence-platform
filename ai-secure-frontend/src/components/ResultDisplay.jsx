import React from "react";

const FINDING_LABELS = {
  passwords: { label: "Passwords", icon: "🔑" },
  weak_passwords: { label: "Weak Passwords", icon: "⚠️" },
  emails: { label: "Emails", icon: "📧" },
  api_keys: { label: "API Keys", icon: "🔐" },
  credit_cards: { label: "Credit Cards", icon: "💳" },
  phones: { label: "Phone Numbers", icon: "📞" },
  ips: { label: "IP Addresses", icon: "🌐" },
  stack_traces: { label: "Stack Traces", icon: "🔥" },
  debug_leaks: { label: "Debug Leaks", icon: "🐛" },
};

const RISK_COLORS = {
  weak_password: "#ef4444",
  password: "#f59e0b",
  api_key: "#ef4444",
  credit_card: "#ef4444",
  email: "#3b82f6",
  phone: "#3b82f6",
  ip: "#6b7280",
  stack_trace: "#f97316",
  debug_leak: "#a855f7",
};

const ResultDisplay = ({ data }) => {
  if (!data) return null;

  if (data.error) {
    return (
      <div className="results-section">
        <div className="risk-header" style={{ borderColor: "rgba(239, 68, 68, 0.3)" }}>
          <div style={{ color: "#f87171", fontSize: "14px" }}>⚠️ {data.error}</div>
        </div>
      </div>
    );
  }

  // Support both old and new API format
  const riskScore = data.risk_score ?? data.risk_result?.total_score ?? 0;
  const riskLevel = data.risk_level ?? data.risk_result?.risk_level ?? "LOW";
  const counts = data.counts ?? data.risk_result?.counts ?? {};
  const examples = data.examples ?? data.risk_result?.examples ?? {};
  const findings = data.findings ?? data.risk_result?.details ?? [];
  const insights = data.insights ?? data.ai_analysis ?? {};
  const action = data.action ?? "allowed";
  const logAnalysis = data.log_analysis ?? null;

  const riskClass = riskLevel.toLowerCase();

  // Active findings (count > 0)
  const activeFindings = Object.entries(counts).filter(([, count]) => count > 0);

  return (
    <div className="results-section">
      {/* Action Banner */}
      {action === "blocked" && (
        <div className="action-banner blocked">
          🚫 Content BLOCKED — High risk detected. Policy enforcement active.
        </div>
      )}
      {action === "review_required" && (
        <div className="action-banner review">
          ⚠️ Review Required — High risk content detected.
        </div>
      )}

      {/* Risk Header */}
      <div className="risk-header">
        <div className="risk-header-left">
          <div className={`risk-score-ring ${riskClass}`}>
            <span className="score-value">{riskScore}</span>
            <span className="score-max">/10</span>
          </div>
          <div>
            <div className={`risk-badge ${riskClass}`}>{riskLevel}</div>
            <div className="risk-label" style={{ marginTop: "6px" }}>Security Risk Level</div>
          </div>
        </div>
        {data.content_type && (
          <div className="content-type-badge">{data.content_type.toUpperCase()}</div>
        )}
      </div>

      {/* Findings Grid */}
      <div className="findings-section">
        <h3>🔍 Detected Findings</h3>
        {activeFindings.length === 0 ? (
          <div className="no-findings"><p>✅ No sensitive data detected</p></div>
        ) : (
          <div className="findings-grid">
            {activeFindings.map(([key, count]) => {
              const meta = FINDING_LABELS[key] || { label: key, icon: "🔹" };
              const exList = (examples || {})[key] || [];
              return (
                <div key={key} className="finding-card">
                  <div className="finding-card-header">
                    <span className="finding-type">{meta.icon} {meta.label}</span>
                    <span className="finding-count">{count}</span>
                  </div>
                  {exList.length > 0 && (
                    <ul className="finding-examples">
                      {exList.slice(0, 5).map((ex, i) => <li key={i}>{ex}</li>)}
                    </ul>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Log Viewer — line-by-line with risk markers */}
      {findings.length > 0 && (
        <div className="findings-section">
          <h3>📋 Sensitive Lines</h3>
          <div className="log-viewer">
            {findings.slice(0, 20).map((f, i) => {
              const topTag = f.sensitive?.[0] || "";
              const color = RISK_COLORS[topTag] || "#6b7280";
              return (
                <div key={i} className="log-line" style={{ borderLeftColor: color }}>
                  <span className="log-line-num">{f.line ?? i + 1}</span>
                  <span className="log-line-text">{f.masked_text || f.text}</span>
                  <div className="log-line-tags">
                    {(f.sensitive || []).map((tag, j) => (
                      <span key={j} className="log-tag" style={{ background: `${RISK_COLORS[tag] || "#6b7280"}22`, color: RISK_COLORS[tag] || "#6b7280" }}>
                        {tag.replace("_", " ")}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Log Analysis Panel */}
      {logAnalysis && (
        <div className="findings-section">
          <h3>📊 Log Analysis</h3>
          <div className="log-stats-grid">
            <div className="log-stat">
              <span className="log-stat-value error-val">{logAnalysis.error_count}</span>
              <span className="log-stat-label">Errors</span>
            </div>
            <div className="log-stat">
              <span className="log-stat-value warn-val">{logAnalysis.warning_count}</span>
              <span className="log-stat-label">Warnings</span>
            </div>
            <div className="log-stat">
              <span className="log-stat-value trace-val">{logAnalysis.stack_traces}</span>
              <span className="log-stat-label">Stack Traces</span>
            </div>
            <div className="log-stat">
              <span className="log-stat-value debug-val">{logAnalysis.debug_leaks}</span>
              <span className="log-stat-label">Debug Leaks</span>
            </div>
          </div>
          {logAnalysis.anomalies && logAnalysis.anomalies.length > 0 && (
            <div className="anomalies-panel">
              <h4>🚨 Anomalies Detected</h4>
              <ul className="anomaly-list">
                {logAnalysis.anomalies.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* AI Analysis */}
      {insights && (typeof insights === "object") && (
        <div className="ai-section">
          <h3>🧠 AI Security Analysis</h3>
          {insights.summary && (
            <div className="ai-block">
              <div className="ai-block-label summary-label">Summary</div>
              <p className="ai-summary-text">{insights.summary}</p>
            </div>
          )}
          {insights.why_risky?.length > 0 && (
            <div className="ai-block">
              <div className="ai-block-label risky-label">Why This Is Risky</div>
              <ul className="ai-bullets risky">
                {insights.why_risky.map((item, i) => <li key={i}>{item}</li>)}
              </ul>
            </div>
          )}
          {insights.fixes?.length > 0 && (
            <div className="ai-block">
              <div className="ai-block-label fixes-label">Recommended Fixes</div>
              <ul className="ai-bullets fixes">
                {insights.fixes.map((item, i) => <li key={i}>{item}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Backward compat: string AI analysis */}
      {typeof insights === "string" && (
        <div className="ai-section">
          <h3>🧠 AI Security Analysis</h3>
          <div className="ai-block"><p className="ai-summary-text">{insights}</p></div>
        </div>
      )}
    </div>
  );
};

export default ResultDisplay;