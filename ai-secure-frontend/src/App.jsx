import { useState } from "react";
import InputForm from "./components/InputForm";
import ResultDisplay from "./components/ResultDisplay";
import InfoPanel from "./components/InfoPanel";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  return (
    <div className="app-shell">
      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <div className="logo-area">
            <div className="logo-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <h1>AI Secure Data Analyzer</h1>
              <p className="subtitle">Detect sensitive data &amp; analyze security risks with AI</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Dashboard */}
      <main className="dashboard">
        {/* LEFT COLUMN */}
        <div className="left-column">
          <InputForm setResult={setResult} setLoading={setLoading} loading={loading} />

          {loading && (
            <div className="loading-container">
              <div className="spinner"></div>
              <p>Analyzing data for security risks...</p>
            </div>
          )}

          {result && !loading && <ResultDisplay data={result} />}
        </div>

        {/* RIGHT COLUMN — ALWAYS VISIBLE */}
        <div className="right-column">
          <InfoPanel result={result} />
        </div>
      </main>
    </div>
  );
}