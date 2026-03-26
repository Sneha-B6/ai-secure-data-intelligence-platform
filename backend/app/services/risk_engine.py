"""
Risk Engine module — calculates risk scores and classification from detected data.
Weights per specification, score capped at 10, with per-item and aggregate scoring.
"""
from typing import List, Dict, Any
from app.services.detector import mask_value

# Risk weights per specification
RISK_WEIGHTS = {
    "weak_password": 6,
    "password": 3,
    "api_key": 6,
    "credit_card": 6,
    "email": 2,
    "phone": 2,
    "ip": 1,
    "stack_trace": 2,
    "debug_leak": 1,
}


def calculate_risk(detected_data: List[Dict[str, Any]], should_mask: bool = False) -> Dict[str, Any]:
    """
    Calculate risk score from detected sensitive data.
    Returns: total_score, risk_level, findings, counts, examples.
    """
    total_score = 0
    findings = []

    counts = {
        "passwords": 0,
        "weak_passwords": 0,
        "emails": 0,
        "api_keys": 0,
        "credit_cards": 0,
        "phones": 0,
        "ips": 0,
        "stack_traces": 0,
        "debug_leaks": 0,
    }

    examples = {
        "passwords": [],
        "weak_passwords": [],
        "emails": [],
        "api_keys": [],
        "credit_cards": [],
        "phones": [],
        "ips": [],
    }

    for item in detected_data:
        sensitive = item.get("sensitive", [])
        matched = item.get("matched_values", {})

        if not sensitive:
            continue

        item_score = sum(RISK_WEIGHTS.get(tag, 1) for tag in sensitive)
        total_score += item_score

        # Build display text
        display_text = item.get("text", "")[:200]
        masked_text = None

        if should_mask and matched:
            masked_text = display_text
            for key, val in matched.items():
                if isinstance(val, str) and val in masked_text:
                    masked_text = masked_text.replace(val, mask_value(val))
                elif isinstance(val, list):
                    for v in val:
                        if v in masked_text:
                            masked_text = masked_text.replace(v, mask_value(v))

        # Count and collect examples
        for tag in sensitive:
            if tag == "weak_password":
                counts["weak_passwords"] += 1
                val = matched.get("weak_password", "")
                if val and len(examples["weak_passwords"]) < 5:
                    examples["weak_passwords"].append(mask_value(val))
            elif tag == "password":
                counts["passwords"] += 1
                val = matched.get("password", "")
                if val and len(examples["passwords"]) < 5:
                    examples["passwords"].append(mask_value(val))
            elif tag == "api_key":
                counts["api_keys"] += 1
                val = matched.get("api_key", "")
                if val and len(examples["api_keys"]) < 5:
                    examples["api_keys"].append(mask_value(val))
            elif tag == "email":
                counts["emails"] += 1
                vals = matched.get("email", [])
                if isinstance(vals, list):
                    for v in vals:
                        if len(examples["emails"]) < 5:
                            examples["emails"].append(v)
                elif vals and len(examples["emails"]) < 5:
                    examples["emails"].append(vals)
            elif tag == "credit_card":
                counts["credit_cards"] += 1
                val = matched.get("credit_card", "")
                if val and len(examples["credit_cards"]) < 5:
                    examples["credit_cards"].append(mask_value(val))
            elif tag == "phone":
                counts["phones"] += 1
                val = matched.get("phone", "")
                if val and len(examples["phones"]) < 5:
                    examples["phones"].append(mask_value(val))
            elif tag == "ip":
                counts["ips"] += 1
                val = matched.get("ip", "")
                if val and len(examples["ips"]) < 5:
                    examples["ips"].append(val)
            elif tag == "stack_trace":
                counts["stack_traces"] += 1
            elif tag == "debug_leak":
                counts["debug_leaks"] += 1

        finding = {
            "line": item.get("line"),
            "text": masked_text if should_mask and masked_text else display_text,
            "sensitive": sensitive,
            "risk_score": item_score,
        }
        if should_mask and masked_text:
            finding["masked_text"] = masked_text

        findings.append(finding)

    # Cap total at 10
    total_score = min(total_score, 10)

    # Risk classification
    if total_score <= 2:
        risk_level = "LOW"
    elif total_score <= 7:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "findings": findings[:30],
        "counts": counts,
        "examples": examples
    }