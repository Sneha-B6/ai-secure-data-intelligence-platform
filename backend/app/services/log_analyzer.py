"""
Log Analyzer module — performs log-specific analysis on detected data.
Detects: error counts, warning counts, stack traces, debug leaks, anomalies.
"""
from typing import List, Dict, Any
from collections import Counter
import re


def analyze_logs(detected_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Perform log-specific analysis on detected data.
    Returns error/warning counts, stack trace count, debug leaks, anomalies, and suspicious lines.
    """
    error_count = 0
    warning_count = 0
    stack_trace_count = 0
    debug_leak_count = 0
    suspicious_lines = []
    anomalies = []

    # Tracking for anomaly detection
    error_sources = []
    failure_timestamps = []
    ip_counter = Counter()
    auth_failures = 0

    for item in detected_data:
        text = item.get("text", "") or ""
        lower_text = text.lower()
        sensitive = item.get("sensitive", [])

        # --- Error / Warning counting ---
        is_error = bool(re.search(r"\b(error|fail|fatal|critical|exception)\b", lower_text))
        is_warning = bool(re.search(r"\b(warn|warning|deprecated)\b", lower_text))

        if is_error:
            error_count += 1
            suspicious_lines.append({
                "line": item.get("line"),
                "text": text[:200],
                "type": "error"
            })
            # Track error source for anomaly detection
            source_match = re.search(r"(\S+\.(?:py|js|java|go|rb|ts))", text)
            if source_match:
                error_sources.append(source_match.group(1))

        if is_warning:
            warning_count += 1

        # --- Stack trace detection ---
        if "stack_trace" in sensitive:
            stack_trace_count += 1

        # --- Debug leak detection ---
        if "debug_leak" in sensitive:
            debug_leak_count += 1
            suspicious_lines.append({
                "line": item.get("line"),
                "text": text[:200],
                "type": "debug_leak"
            })

        # --- Auth failure tracking ---
        if re.search(r"\b(auth|login|access)\b.*\b(fail|denied|reject|invalid|unauthorized)\b", lower_text):
            auth_failures += 1

        # --- IP tracking for brute-force detection ---
        for val in item.get("matched_values", {}).get("ip", []) if isinstance(item.get("matched_values", {}).get("ip"), list) else [item.get("matched_values", {}).get("ip", "")]:
            if val:
                ip_counter[val] += 1

    # --- Anomaly detection ---

    # Repeated errors from same source
    source_counts = Counter(error_sources)
    for source, count in source_counts.most_common(3):
        if count >= 3:
            anomalies.append(f"Repeated errors ({count}x) from {source}")

    # High error rate
    total_lines = len(detected_data)
    if total_lines > 0 and error_count / total_lines > 0.3:
        anomalies.append(f"High error rate: {error_count}/{total_lines} lines ({int(error_count/total_lines*100)}%)")

    # Auth brute-force pattern
    if auth_failures >= 3:
        anomalies.append(f"Possible brute-force: {auth_failures} authentication failures detected")

    # Suspicious IP activity
    for ip, count in ip_counter.most_common(3):
        if count >= 5:
            anomalies.append(f"Suspicious IP activity: {ip} appears {count} times")

    # Stack trace in production
    if stack_trace_count > 0:
        anomalies.append(f"{stack_trace_count} stack trace(s) detected — possible production error exposure")

    # Debug leaks
    if debug_leak_count > 0:
        anomalies.append(f"{debug_leak_count} debug/verbose log(s) detected — possible information leak")

    return {
        "error_count": error_count,
        "warning_count": warning_count,
        "stack_traces": stack_trace_count,
        "debug_leaks": debug_leak_count,
        "anomalies": anomalies[:10],
        "suspicious_lines": suspicious_lines[:20]
    }