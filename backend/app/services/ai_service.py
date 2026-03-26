"""
AI Service module — generates structured security analysis using Groq LLM.
Supports log-specific prompting with actual findings references.
"""
import os
import re
from groq import Groq

client = None


def _get_client():
    global client
    if client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set in environment")
        client = Groq(api_key=api_key)
    return client


def generate_ai_analysis(content: str, risk_result: dict, log_analysis: dict = None) -> dict:
    """
    Generate structured AI security analysis using Groq LLM.
    Returns dict: {summary, why_risky, fixes}
    """
    truncated = content[:1500] if len(content) > 1500 else content

    # Build log-specific context
    log_context = ""
    if log_analysis:
        log_context = f"""
LOG ANALYSIS:
- Errors: {log_analysis.get('error_count', 0)}
- Warnings: {log_analysis.get('warning_count', 0)}
- Stack Traces: {log_analysis.get('stack_traces', 0)}
- Debug Leaks: {log_analysis.get('debug_leaks', 0)}
- Anomalies: {', '.join(log_analysis.get('anomalies', [])) or 'None'}
"""

    prompt = f"""You are a strict cybersecurity analyst. Analyze the following data and provide a security assessment.

RULES:
- Be concise and precise
- No fluff, no repetition
- Max 5 bullet points per section
- Reference actual findings below — do NOT hallucinate
- Each bullet must start with "- "

DETECTED DATA:
Risk Score: {risk_result.get('total_score', 0)}/10
Risk Level: {risk_result.get('risk_level', 'LOW')}
Findings: {risk_result.get('counts', {})}
{log_context}
SAMPLE CONTENT:
{truncated[:500]}

Respond EXACTLY in this format:

SUMMARY:
- (1-3 bullets summarizing what was found)

WHY_RISKY:
- (1-5 bullets explaining why this data is risky)

FIXES:
- (1-5 bullets with specific recommended fixes)"""

    try:
        groq_client = _get_client()
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Respond only in the exact format requested. Be concise. Reference actual detected findings."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=600,
        )
        return _parse_ai_response(response.choices[0].message.content)

    except Exception as e:
        return {
            "summary": f"AI analysis error: {str(e)[:100]}",
            "why_risky": ["Unable to generate detailed risk analysis."],
            "fixes": ["Check GROQ_API_KEY configuration and retry."]
        }


def _parse_ai_response(text: str) -> dict:
    """Parse structured AI response into sections."""
    result = {"summary": "", "why_risky": [], "fixes": []}
    text = text.strip()

    summary_match = re.search(r"SUMMARY:\s*\n(.*?)(?=\n\s*WHY_RISKY:|\n\s*FIXES:|$)", text, re.DOTALL | re.IGNORECASE)
    risky_match = re.search(r"WHY_RISKY:\s*\n(.*?)(?=\n\s*FIXES:|$)", text, re.DOTALL | re.IGNORECASE)
    fixes_match = re.search(r"FIXES:\s*\n(.*?)$", text, re.DOTALL | re.IGNORECASE)

    def extract_bullets(section: str) -> list:
        bullets = []
        for line in section.strip().split("\n"):
            line = re.sub(r"^[-*•]\s*", "", line.strip())
            line = re.sub(r"^\d+\.\s*", "", line)
            if line:
                bullets.append(line)
        return bullets[:5]

    if summary_match:
        bullets = extract_bullets(summary_match.group(1))
        result["summary"] = " ".join(bullets) if bullets else text[:200]
    else:
        result["summary"] = text[:200]

    if risky_match:
        result["why_risky"] = extract_bullets(risky_match.group(1))
    if fixes_match:
        result["fixes"] = extract_bullets(fixes_match.group(1))

    if not result["why_risky"]:
        result["why_risky"] = ["Could not extract specific risk factors."]
    if not result["fixes"]:
        result["fixes"] = ["Review all detected sensitive data and remediate."]

    return result