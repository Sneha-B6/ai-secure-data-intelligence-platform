"""
Policy Engine module — applies configurable policies to analysis results.
Supports: masking, high-risk blocking, log analysis control.
"""
from typing import Dict, Any


def apply_policies(risk_result: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply policy rules to the analysis result:
    - mask: sensitive values are already masked in risk_engine if enabled
    - block_high_risk: adds a blocking flag and warning action
    - log_analysis: controls whether log-specific output is included

    Returns the action string and any policy metadata.
    """
    action = "allowed"
    policy_flags = []

    total_score = risk_result.get("total_score", 0)
    risk_level = risk_result.get("risk_level", "LOW")

    # --- Block High Risk ---
    if options.get("block_high_risk", False) and risk_level == "HIGH":
        action = "blocked"
        policy_flags.append("Content blocked due to HIGH risk level")

    # --- Masking ---
    if options.get("mask", False):
        policy_flags.append("Sensitive values masked in output")

    # --- Log Analysis ---
    if options.get("log_analysis", True):
        policy_flags.append("Log-specific analysis enabled")

    # Determine action text
    if action == "allowed":
        if risk_level == "HIGH":
            action = "review_required"
        elif risk_level == "MEDIUM":
            action = "caution"
        else:
            action = "allowed"

    return {
        "action": action,
        "policy_flags": policy_flags,
        "policies_applied": {
            "mask": options.get("mask", False),
            "block_high_risk": options.get("block_high_risk", False),
            "log_analysis": options.get("log_analysis", True),
        }
    }
