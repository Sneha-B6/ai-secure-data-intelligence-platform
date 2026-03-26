from pydantic import BaseModel, Field
from typing import Literal, Dict, List, Optional


class AnalysisOptions(BaseModel):
    """Policy engine options for controlling analysis behavior."""
    mask: bool = Field(
        default=False,
        description="Mask sensitive values in output (e.g., ****1234)"
    )
    block_high_risk: bool = Field(
        default=False,
        description="Flag and block high-risk content"
    )
    log_analysis: bool = Field(
        default=True,
        description="Enable log-specific analysis (stack traces, anomalies)"
    )


class AnalyzeRequest(BaseModel):
    input_type: Literal["log", "text", "raw"] = Field(
        ...,
        description="Type of input data",
        example="log"
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Input content to analyze",
        example="password=1234"
    )
    options: AnalysisOptions = Field(
        default_factory=AnalysisOptions,
        description="Policy engine options"
    )


class Finding(BaseModel):
    line: Optional[int] = None
    text: str
    sensitive: List[str]
    risk_score: int
    masked_text: Optional[str] = None


class LogAnalysisResult(BaseModel):
    error_count: int = 0
    warning_count: int = 0
    stack_traces: int = 0
    debug_leaks: int = 0
    anomalies: List[str] = []
    suspicious_lines: List[dict] = []


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    action: str
    insights: dict
    counts: dict
    examples: Dict[str, List[str]]
    log_analysis: Optional[LogAnalysisResult] = None