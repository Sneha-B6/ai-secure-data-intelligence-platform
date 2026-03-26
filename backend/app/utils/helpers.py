from typing import Any, Dict


def safe_get(data: Dict, key: str, default: Any = None) -> Any:
    """
    Safely get a value from a dictionary.
    Returns default if key is missing or value is None.
    """
    value = data.get(key, default)
    return value if value is not None else default


def safe_str(value: Any) -> str:
    """
    Safely convert any value to string.
    Prevents None from becoming 'None'.
    """
    return str(value) if value is not None else ""


def is_empty(value: Any) -> bool:
    """
    Check if a value is empty (None, empty string, empty list, etc.)
    """
    return value is None or value == "" or value == [] or value == {}