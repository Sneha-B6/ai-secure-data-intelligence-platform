import React, { useState, useRef } from "react";
import axios from "axios";

const handleSubmit = async () => {
  try {
    const response = await axios.post(
      `${import.meta.env.VITE_API_URL}/api/analyze`,
      {
        text: inputText, // or whatever your payload is
      }
    );

    console.log(response.data);
  } catch (error) {
    console.error(error);
  }
};

const BASE_URL = import.meta.env.VITE_API_URL;

const InputForm = ({ setResult, setLoading, loading }) => {
  const [content, setContent] = useState("");
  const [mode, setMode] = useState("text");
  const [inputType, setInputType] = useState("text");
  const [file, setFile] = useState(null);
  const [options, setOptions] = useState({
    mask: false,
    block_high_risk: false,
    log_analysis: true,
  });
  const fileInputRef = useRef(null);

  const toggleOption = (key) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleTextSubmit = async () => {
    if (!content.trim() || loading) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post(`${BASE_URL}/api/analyze`, {
        input_type: inputType,
        content,
        options,
      });
      setResult(res.data);
    } catch (err) {
      setResult({ error: "Backend connection failed. Make sure the server is running on port 8000." });
    } finally {
      setLoading(false);
    }
  };

  const handleFileSubmit = async () => {
    if (!file || loading) return;
    const formData = new FormData();
    formData.append("file", file);
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post(`${BASE_URL}/api/analyze-file`, formData);
      setResult(res.data);
    } catch (err) {
      setResult({ error: "File processing failed. Ensure the file is valid and server is running." });
    } finally {
      setLoading(false);
    }
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) setFile(droppedFile);
  };

  return (
    <div className="input-card">
      <h2>Security Analysis Input</h2>

      {/* Mode Toggle */}
      <div className="mode-toggle">
        <button className={mode === "text" ? "active" : ""} onClick={() => setMode("text")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <polyline points="14,2 14,8 20,8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
          </svg>
          Text Input
        </button>
        <button className={mode === "file" ? "active" : ""} onClick={() => setMode("file")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
            <polyline points="17,8 12,3 7,8" />
            <line x1="12" y1="3" x2="12" y2="15" />
          </svg>
          File Upload
        </button>
      </div>

      {/* Text Input */}
      {mode === "text" && (
        <>
          {/* Input Type Selector */}
          <div className="input-type-row">
            <label className="input-type-label">Input Type:</label>
            <div className="input-type-pills">
              {["text", "log", "raw"].map((t) => (
                <button
                  key={t}
                  className={`pill ${inputType === t ? "active" : ""}`}
                  onClick={() => setInputType(t)}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <textarea
            className="input-textarea"
            placeholder={
              inputType === "log"
                ? "Paste server logs here...\n\nExample:\n2024-01-15 ERROR auth.login: Failed login for admin from 192.168.1.50\npassword=admin123\napi_key=sk-abc123def456"
                : "Paste logs, config files, credentials, API responses...\n\nExample:\npassword=admin123\napi_key=sk-abc123def456\nemail: user@company.com"
            }
            value={content}
            onChange={(e) => setContent(e.target.value)}
            spellCheck={false}
          />

          {/* Policy Options */}
          <div className="options-row">
            <label className={`option-check ${options.mask ? "checked" : ""}`} onClick={() => toggleOption("mask")}>
              <span className="check-box">{options.mask ? "✓" : ""}</span>
              Mask Values
            </label>
            <label className={`option-check ${options.block_high_risk ? "checked" : ""}`} onClick={() => toggleOption("block_high_risk")}>
              <span className="check-box">{options.block_high_risk ? "✓" : ""}</span>
              Block High Risk
            </label>
            <label className={`option-check ${options.log_analysis ? "checked" : ""}`} onClick={() => toggleOption("log_analysis")}>
              <span className="check-box">{options.log_analysis ? "✓" : ""}</span>
              Log Analysis
            </label>
          </div>

          <button className="analyze-btn" onClick={handleTextSubmit} disabled={!content.trim() || loading}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            {loading ? "Analyzing..." : "Analyze for Risks"}
          </button>
        </>
      )}

      {/* File Upload */}
      {mode === "file" && (
        <>
          <div
            className={`file-upload-area ${file ? "has-file" : ""}`}
            onClick={() => fileInputRef.current?.click()}
            onDrop={handleFileDrop}
            onDragOver={(e) => e.preventDefault()}
          >
            <div className="upload-icon">{file ? "✅" : "📄"}</div>
            <div className="upload-text">
              {file ? "File selected — ready to analyze" : "Click or drag a file here"}
            </div>
            <div className="upload-formats">.txt · .log · .json · .pdf · .doc · .docx</div>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.log,.json,.pdf,.doc,.docx"
            onChange={(e) => setFile(e.target.files[0])}
            style={{ display: "none" }}
          />
          {file && (
            <div className="file-name-display">
              <span className="file-icon">📎</span>
              {file.name}
              <span style={{ marginLeft: "auto", fontSize: "12px", color: "#6b7280" }}>
                {(file.size / 1024).toFixed(1)} KB
              </span>
            </div>
          )}
          <button className="analyze-btn" onClick={handleFileSubmit} disabled={!file || loading}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="17,8 12,3 7,8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
            {loading ? "Processing..." : "Upload & Analyze"}
          </button>
        </>
      )}
    </div>
  );
};

export default InputForm;
