"""
Parser module — transforms raw input into structured line-by-line data.
Handles log, text, and raw input types.
"""
from typing import List, Dict
import re


def parse_input(input_type: str, content: str) -> List[Dict]:
    """
    Parse input content into a list of structured items.
    Each item has: line (int), text (str), raw (str, optional)
    """
    content = content.strip()

    if not content:
        return []

    if input_type == "log":
        return _parse_log(content)

    elif input_type == "text":
        return _parse_text(content)

    elif input_type == "raw":
        return [{"line": 1, "text": content, "raw": content}]

    # Fallback
    return _parse_text(content)


def _parse_log(content: str) -> List[Dict]:
    """Parse log content line-by-line with line numbers."""
    lines = content.split("\n")
    parsed = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped:
            parsed.append({
                "line": i,
                "text": stripped,
                "original": line
            })

    return parsed


def _parse_text(content: str) -> List[Dict]:
    """Parse text content line-by-line."""
    lines = content.split("\n")
    parsed = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped:
            parsed.append({
                "line": i,
                "text": stripped
            })

    return parsed