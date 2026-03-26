"""
Detector module — detects sensitive data in parsed items using compiled regex.
Supports: passwords, emails, API keys, credit cards, phones, IPs, stack traces, debug leaks.
"""
import re
from typing import List, Dict, Any

# -----------------------------------------------
# Compiled detection patterns
# -----------------------------------------------
PATTERNS = {
    "password": re.compile(
        r"(?:password|passwd|pwd|pass)\s*[:=]\s*(\S+)",
        re.IGNORECASE
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b"
    ),
    "api_key": re.compile(
        r"(?:api[_\-]?key|token|secret|auth[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret|bearer)\s*[:=]\s*(\S+)",
        re.IGNORECASE
    ),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}\b"
    ),
    "phone": re.compile(
        r"(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"
    ),
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "stack_trace": re.compile(
        r"(?:Traceback|Exception|Error|FATAL|panic|at\s+\S+\.\S+\(|File\s+\".+\",\s+line\s+\d+)",
        re.IGNORECASE
    ),
    "debug_leak": re.compile(
        r"(?:DEBUG|VERBOSE|TRACE)\s*[:\-]?\s*.{10,}",
        re.IGNORECASE
    ),
}

# IPs to exclude (non-sensitive)
EXCLUDED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "0.0.0.1"}

# Common weak password patterns
WEAK_PATTERNS = [
    "123", "password", "abc", "qwerty", "admin",
    "letmein", "welcome", "monkey", "dragon", "master",
    "login", "test", "default", "pass", "1234"
]


def is_weak_password(value: str) -> bool:
    """Check if a password is weak based on length, complexity, and common patterns."""
    value = value.strip().strip("'\"")
    if len(value) < 8:
        return True
    if value.isdigit():
        return True
    if value.isalpha():
        return True
    return any(p in value.lower() for p in WEAK_PATTERNS)


def luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def mask_value(value: str, visible: int = 4) -> str:
    """Mask sensitive data, showing only last few chars."""
    if len(value) <= visible:
        return "****"
    return "*" * (len(value) - visible) + value[-visible:]


def detect_sensitive_data(parsed_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all detection patterns on parsed data.
    Returns enriched items with: sensitive[], risk_score, matched_values{}
    """
    results = []

    for item in parsed_data:
        text = item.get("text", "") or ""
        sensitive = []
        matched_values = {}

        # PASSWORD
        pw_match = PATTERNS["password"].search(text)
        if pw_match:
            value = pw_match.group(1).strip("'\"")
            if is_weak_password(value):
                sensitive.append("weak_password")
                matched_values["weak_password"] = value
            else:
                sensitive.append("password")
                matched_values["password"] = value

        # API KEY
        api_match = PATTERNS["api_key"].search(text)
        if api_match:
            value = api_match.group(1).strip("'\"")
            sensitive.append("api_key")
            matched_values["api_key"] = value

        # EMAIL
        email_matches = PATTERNS["email"].findall(text)
        if email_matches:
            sensitive.append("email")
            matched_values["email"] = email_matches

        # CREDIT CARD (with Luhn validation)
        cc_matches = PATTERNS["credit_card"].findall(text)
        for cc in cc_matches:
            digits_only = re.sub(r"[\s\-]", "", cc)
            if luhn_check(digits_only):
                if "credit_card" not in sensitive:
                    sensitive.append("credit_card")
                matched_values["credit_card"] = digits_only

        # PHONE (skip if credit card already matched on same line)
        if "credit_card" not in sensitive:
            phone_matches = PATTERNS["phone"].findall(text)
            if phone_matches:
                sensitive.append("phone")
                matched_values["phone"] = phone_matches[0].strip()

        # IP ADDRESS
        ip_matches = PATTERNS["ip"].findall(text)
        valid_ips = [ip for ip in ip_matches if ip not in EXCLUDED_IPS]
        if valid_ips:
            sensitive.append("ip")
            matched_values["ip"] = valid_ips[0]

        # STACK TRACE
        if PATTERNS["stack_trace"].search(text):
            if "stack_trace" not in sensitive:
                sensitive.append("stack_trace")

        # DEBUG LEAK
        if PATTERNS["debug_leak"].search(text):
            if "debug_leak" not in sensitive:
                sensitive.append("debug_leak")

        results.append({
            **item,
            "sensitive": sensitive,
            "is_sensitive": bool(sensitive),
            "matched_values": matched_values
        })

    return results