"""
Analysis Routes — implements the modular processing pipeline:
Input → Parser → Detector → Log Analyzer → Risk Engine → Policy Engine → AI → Response
"""
from fastapi import APIRouter, UploadFile, File
from app.models.schema import AnalyzeRequest
from app.services.parser import parse_input
from app.services.detector import detect_sensitive_data
from app.services.log_analyzer import analyze_logs
from app.services.risk_engine import calculate_risk
from app.services.policy_engine import apply_policies
from app.services.ai_service import generate_ai_analysis
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Analysis"])


def _run_pipeline(content: str, input_type: str, options: dict) -> dict:
    """
    Core analysis pipeline:
    1. Parse → 2. Detect → 3. Log Analyze → 4. Risk Score → 5. Policy → 6. AI
    """
    should_mask = options.get("mask", False)
    enable_log_analysis = options.get("log_analysis", True)

    # Step 1: Parse input into structured lines
    parsed = parse_input(input_type, content)
    logger.info(f"Parsed {len(parsed)} lines (type={input_type})")

    # Step 2: Detect sensitive data
    detected = detect_sensitive_data(parsed)
    sensitive_count = sum(1 for d in detected if d.get("is_sensitive"))
    logger.info(f"Detected {sensitive_count} sensitive lines")

    # Step 3: Log analysis (if enabled and input is log type)
    log_result = None
    if enable_log_analysis and input_type == "log":
        log_result = analyze_logs(detected)
        logger.info(f"Log analysis: {log_result.get('error_count', 0)} errors, {len(log_result.get('anomalies', []))} anomalies")

    # Step 4: Calculate risk
    risk_result = calculate_risk(detected, should_mask=should_mask)
    logger.info(f"Risk: {risk_result['total_score']}/10 ({risk_result['risk_level']})")

    # Step 5: Apply policies
    policy_result = apply_policies(risk_result, options)

    # Step 6: AI analysis
    try:
        ai_analysis = generate_ai_analysis(content, risk_result, log_result)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        ai_analysis = {
            "summary": "AI analysis unavailable.",
            "why_risky": ["Could not connect to AI service."],
            "fixes": ["Retry later or check API key configuration."]
        }

    # Build summary
    parts = []
    counts = risk_result.get("counts", {})
    if counts.get("weak_passwords", 0) + counts.get("passwords", 0) > 0:
        parts.append(f"{counts.get('weak_passwords', 0) + counts.get('passwords', 0)} password(s)")
    if counts.get("api_keys", 0) > 0:
        parts.append(f"{counts['api_keys']} API key(s)")
    if counts.get("credit_cards", 0) > 0:
        parts.append(f"{counts['credit_cards']} credit card(s)")
    if counts.get("emails", 0) > 0:
        parts.append(f"{counts['emails']} email(s)")
    if counts.get("phones", 0) > 0:
        parts.append(f"{counts['phones']} phone(s)")
    if counts.get("ips", 0) > 0:
        parts.append(f"{counts['ips']} IP(s)")
    if counts.get("stack_traces", 0) > 0:
        parts.append(f"{counts['stack_traces']} stack trace(s)")
    if counts.get("debug_leaks", 0) > 0:
        parts.append(f"{counts['debug_leaks']} debug leak(s)")

    summary_text = f"Detected {', '.join(parts)}." if parts else "No sensitive data detected."

    # Build spec-compliant response
    return {
        "summary": summary_text,
        "content_type": input_type,
        "findings": risk_result.get("findings", []),
        "risk_score": risk_result["total_score"],
        "risk_level": risk_result["risk_level"],
        "action": policy_result["action"],
        "insights": ai_analysis,
        "counts": risk_result.get("counts", {}),
        "examples": risk_result.get("examples", {}),
        "log_analysis": log_result,
        "policies": policy_result.get("policies_applied", {}),
    }


# -----------------------------------
# Text API
# -----------------------------------
@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    logger.info(f"POST /analyze — type={request.input_type}, len={len(request.content)}")

    options = request.options.model_dump() if request.options else {}
    return _run_pipeline(request.content, request.input_type, options)


# -----------------------------------
# File API
# -----------------------------------
@router.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    from app.services.file_parser import extract_text

    logger.info(f"POST /analyze-file — filename={file.filename}")

    try:
        file_bytes = await file.read()
        content = extract_text(file_bytes, file.filename)

        if not content or not content.strip():
            return {"error": "Could not extract content. Ensure the file is not empty or corrupted."}

        # Determine input type from extension
        fname = file.filename.lower()
        if fname.endswith(".log"):
            input_type = "log"
        else:
            input_type = "text"

        options = {"mask": False, "block_high_risk": False, "log_analysis": True}
        return _run_pipeline(content, input_type, options)

    except Exception as e:
        logger.error(f"File processing failed: {e}")
        return {"error": f"File processing failed: {str(e)}"}