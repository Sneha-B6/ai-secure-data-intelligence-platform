# AI Secure Data Intelligence Platform

A production-grade, AI-powered platform for detecting sensitive data in logs, configs, and files — with real-time risk scoring, policy enforcement, and structured AI analysis.

## Problem Statement

Organizations constantly handle sensitive data — passwords, API keys, credit cards, and PII — across logs, configuration files, and documents. Accidental exposure of this data leads to security breaches, compliance violations, and financial loss. Manual review is slow, inconsistent, and error-prone.

**This platform automates sensitive data detection, risk assessment, and remediation advice** using a modular detection pipeline backed by AI.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (React + Vite)              │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ InputForm│  │ResultDisplay │  │    InfoPanel        │ │
│  │ (text/   │  │(risk badge,  │  │(scoring, policies, │ │
│  │  file)   │  │ log viewer,  │  │ detection summary) │ │
│  │          │  │ AI analysis) │  │                    │ │
│  └──────────┘  └──────────────┘  └────────────────────┘ │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP (REST API)
┌─────────────────────▼───────────────────────────────────┐
│                  Backend (FastAPI)                        │
│                                                          │
│  POST /api/analyze    POST /api/analyze-file             │
│                                                          │
│  Pipeline:                                               │
│  Input → Parser → Detector → Log Analyzer                │
│        → Risk Engine → Policy Engine → AI Analysis       │
│                                                          │
│  Services:                                               │
│  ┌────────┐ ┌──────────┐ ┌──────────────┐               │
│  │ Parser │ │ Detector │ │ Log Analyzer │               │
│  └────────┘ └──────────┘ └──────────────┘               │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐     │
│  │ Risk Engine │ │Policy Engine │ │  AI Service   │     │
│  └─────────────┘ └──────────────┘ └──────────────┘     │
│                                          │               │
│                                    Groq LLM API          │
└──────────────────────────────────────────────────────────┘
```

## Features

### Detection Engine
- **7+ sensitive data types**: passwords (weak/strong), API keys, tokens, secrets, credit cards (Luhn-validated), emails, phone numbers, IP addresses
- **Security issue detection**: stack traces, debug leaks, credentials in logs
- **Anomaly detection**: repeated failures, brute-force patterns, suspicious IP activity

### Risk Scoring
| Type | Weight |
|------|--------|
| Weak Password | 6 |
| Strong Password | 3 |
| API Key / Token / Secret | 6 |
| Credit Card | 6 |
| Email | 2 |
| Phone Number | 2 |
| IP Address | 1 |
| Stack Trace | 2 |
| Debug Leak | 1 |

Score capped at 10. Risk levels: LOW (0–2), MEDIUM (3–7), HIGH (8–10).

### Policy Engine
- **Mask**: hide sensitive values in output
- **Block High Risk**: reject/flag HIGH risk content
- **Log Analysis**: enable log-specific detection (stack traces, anomalies)

### AI Analysis (Groq LLM)
- Structured output: Summary, Why Risky, Fixes
- Max 5 bullets per section
- References actual detected findings

### File Support
`.txt` · `.log` · `.json` · `.pdf` · `.doc` · `.docx`

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, Pydantic |
| AI | Groq SDK, Llama 3.3 70B |
| File Parsing | pdfplumber, python-docx |
| Frontend | React 19, Vite 8, Axios |
| Styling | Vanilla CSS (dark theme) |

## Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- Groq API key ([get one here](https://console.groq.com))

### Backend
```bash
cd ai-secure-platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# Start server
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
cd frontend/ai-secure-frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

Open `http://localhost:5173` in your browser.

## API Usage

### POST /api/analyze

**Request:**
```json
{
  "input_type": "log",
  "content": "2024-01-15 ERROR auth: Failed login for admin\npassword=admin123\napi_key=sk-abc123def456",
  "options": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true
  }
}
```

**Response:**
```json
{
  "summary": "Detected 1 password(s), 1 API key(s).",
  "content_type": "log",
  "findings": [
    {
      "line": 2,
      "text": "password=********123",
      "sensitive": ["weak_password"],
      "risk_score": 6,
      "masked_text": "password=********123"
    }
  ],
  "risk_score": 10,
  "risk_level": "HIGH",
  "action": "review_required",
  "insights": {
    "summary": "Critical security exposure detected...",
    "why_risky": ["Weak password exposed in plain text..."],
    "fixes": ["Rotate all exposed credentials immediately..."]
  },
  "counts": { "weak_passwords": 1, "api_keys": 1, ... },
  "examples": { "weak_passwords": ["****n123"], ... },
  "log_analysis": {
    "error_count": 1,
    "warning_count": 0,
    "stack_traces": 0,
    "debug_leaks": 0,
    "anomalies": ["1 stack trace(s) detected..."]
  },
  "policies": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true
  }
}
```

### POST /api/analyze-file
Upload a file via multipart form data. Accepts `.txt`, `.log`, `.json`, `.pdf`, `.doc`, `.docx`.

### GET /health
Returns service health status.

## Project Structure
```
ai-secure-platform/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI app, CORS, middleware
│       ├── models/
│       │   └── schema.py        # Request/response models
│       ├── routes/
│       │   └── analyze.py       # API endpoints + pipeline
│       ├── services/
│       │   ├── parser.py        # Input parsing
│       │   ├── detector.py      # Sensitive data detection
│       │   ├── log_analyzer.py  # Log-specific analysis
│       │   ├── risk_engine.py   # Risk scoring
│       │   ├── policy_engine.py # Policy enforcement
│       │   ├── ai_service.py    # Groq LLM integration
│       │   └── file_parser.py   # File text extraction
│       └── utils/
│           └── helpers.py       # Utility functions
├── frontend/
│   └── ai-secure-frontend/
│       └── src/
│           ├── App.jsx          # Dashboard layout
│           ├── App.css          # Complete styles
│           ├── main.jsx         # Entry point
│           └── components/
│               ├── InputForm.jsx    # Text/file input + options
│               ├── ResultDisplay.jsx # Results + log viewer
│               └── InfoPanel.jsx    # Sidebar info panel
├── requirements.txt
├── .env.example
└── README.md
```

## Challenges & Solutions

1. **False positive credit cards**: Solved with Luhn algorithm validation
2. **Log anomaly detection**: Implemented pattern-based anomaly detection for brute-force, repeated errors, and suspicious IPs
3. **AI hallucination**: Strict prompting with actual findings context prevents fabricated results
4. **RTF/DOC parsing**: Aggressive regex cleanup removes control words and encoding artifacts

## Domain Alignment

**Software Development / AI & Automation Testing** — This platform directly addresses the need for automated security testing in the software development lifecycle, using AI to analyze code artifacts, logs, and configurations for sensitive data exposure.

## Demo

Demo Video (under 60s):  
https://drive.google.com/drive/folders/1-uxP75r-mrLfBPLi04akruteeAiTarmu?usp=drive_link 

The demo showcases:
- Uploading a .log file with sensitive data
- Real-time risk scoring (HIGH risk detection)
- Highlighted lines with risk markers
- AI-generated security insights
- Policy enforcement (Mask + Block High Risk)

## Live Application
 
Frontend: http://localhost:5173  
Backend: http://localhost:8000

## UI Preview

### Dashboard
![Dashboard](./assets/dashboard.png)

### Log Viewer with Risk Highlighting
![Log Viewer](./assets/log-viewer.png)

## Why This Project Stands Out

- Goes beyond regex detection with anomaly detection (brute-force, repeated failures)
- Implements a full modular pipeline (not a single-script solution)
- Combines deterministic detection with AI reasoning (Groq LLM)
- Includes a policy engine for real-world security enforcement
- Provides visual risk mapping via a structured UI log viewer
