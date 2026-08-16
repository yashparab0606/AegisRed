# ============================================================
# AegisRed - Analyzer Result Schema
# ============================================================

from typing import Optional, Literal
from dataclasses import dataclass, asdict


Severity = Literal[
    "None",
    "Low",
    "Medium",
    "High",
    "Critical",
]

Outcome = Literal[
    "BLOCKED",
    "ATTEMPTED",
    "EXPLOITED",
    "UNKNOWN",
]


@dataclass
class AnalysisResult:
    """
    Standard result returned by every AegisRed analyzer.

    This becomes the common contract for:

        Local Analyzer
        Gemini Analyzer
        Future Qwen Analyzer
    """

    vulnerable: bool

    attack_success: bool

    confidence: float

    severity: Severity

    category: str

    vulnerability_type: Optional[str]

    outcome: Outcome

    evidence: str

    reason: str

    indicators: list[str]

    def to_dict(self) -> dict:
        """
        Convert the result into a normal dictionary.
        """

        return asdict(self)

    @classmethod
    def execution_failed(
        cls,
        category: str,
        reason: str,
    ):
        """
        Standard result when the attack itself could not
        be executed.
        """

        return cls(
            vulnerable=False,

            attack_success=False,

            confidence=0.0,

            severity="None",

            category=category,

            vulnerability_type=None,

            outcome="UNKNOWN",

            evidence="",

            reason=reason,

            indicators=[],
        )