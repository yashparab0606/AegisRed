# ============================================================
# AegisRed - Main Attack Executor
# ============================================================
#
# Stage 3 of the security assessment.
#
# Responsibility:
#     Execute one generated attack against a DVAA target
#     and return a structured execution record.
#
# This module does NOT:
#     - select targets
#     - perform reconnaissance
#     - generate attacks
#     - analyze responses
#     - decide vulnerabilities
#     - run multiple attack categories
#
# Those responsibilities belong to other pipeline components.
#
# Flow:
#
#     Generated Attack
#           |
#           v
#     MainAttackExecutor
#           |
#           v
#     DVAAOpenAIAdapter
#           |
#           v
#     Target Agent
#           |
#           v
#     Target Response
#
# ============================================================

from datetime import datetime
from typing import Any


class MainAttackExecutor:
    """
    Executes generated attacks against a DVAA target.

    The executor uses the existing DVAA adapter for communication.
    It records the execution result but does not analyze the
    target response.
    """

    def __init__(self, adapter):
        """
        Initialize the attack executor.

        Args:
            adapter:
                An initialized DVAAOpenAIAdapter instance.
        """

        self.adapter = adapter

    # ========================================================
    # EXECUTE ATTACK
    # ========================================================

    def execute(
        self,
        attack: str,
        category: str,
        attempt: int = 1,
        conversation: list | None = None,
    ) -> dict[str, Any]:
        """
        Execute one attack against the target.

        Args:
            attack:
                Generated attack prompt.

            category:
                Attack category.

            attempt:
                Attempt number within the category.

            conversation:
                Optional conversation history for multi-turn
                attacks.

        Returns:
            Structured execution record.
        """

        start_time = datetime.utcnow()

        try:

            result = self.adapter.send_message(
                message=attack,
                conversation=conversation,
            )

            end_time = datetime.utcnow()

            execution_time_ms = (
                end_time - start_time
            ).total_seconds() * 1000

            return self._build_execution_record(
                success=True,
                attack=attack,
                category=category,
                attempt=attempt,
                result=result,
                execution_time_ms=execution_time_ms,
            )

        except Exception as exc:

            end_time = datetime.utcnow()

            execution_time_ms = (
                end_time - start_time
            ).total_seconds() * 1000

            return self._build_execution_record(
                success=False,
                attack=attack,
                category=category,
                attempt=attempt,
                result=None,
                execution_time_ms=execution_time_ms,
                error=str(exc),
            )

    # ========================================================
    # BUILD EXECUTION RECORD
    # ========================================================

    def _build_execution_record(
        self,
        success: bool,
        attack: str,
        category: str,
        attempt: int,
        result: dict[str, Any] | None,
        execution_time_ms: float,
        error: str | None = None,
    ) -> dict[str, Any]:
        """
        Build the normalized execution record.

        This record becomes the input contract for the
        Response Analyzer.
        """

        result = result or {}

        return {
            "success": success,

            "timestamp": datetime.utcnow().isoformat(),

            "target": result.get(
                "target",
                getattr(
                    self.adapter,
                    "target_name",
                    None,
                ),
            ),

            "category": category,

            "attempt": attempt,

            "attack": attack,

            "response": result.get(
                "message",
                "",
            ),

            "tool_calls": result.get(
                "tool_calls",
                [],
            ),

            "status_code": result.get(
                "status_code",
            ),

            "raw_response": result.get(
                "raw",
                {},
            ),

            "debug_raw_response": result.get(
                "raw",
                {},
            ),

            "execution_time_ms": execution_time_ms,

            "error": error,
        }

    # ========================================================
    # RESPONSE ACCESSOR
    # ========================================================

    @staticmethod
    def get_response(
        execution_record: dict[str, Any],
    ) -> str:
        """
        Return only the target's textual response.

        Useful for downstream components such as the
        Response Analyzer.
        """

        return execution_record.get(
            "response",
            "",
        )

    # ========================================================
    # EXECUTION STATUS
    # ========================================================

    @staticmethod
    def was_successful(
        execution_record: dict[str, Any],
    ) -> bool:
        """
        Determine whether the attack was successfully sent
        and a response was received.

        This is execution status only.

        It does NOT mean the target was vulnerable.
        """

        return execution_record.get(
            "success",
            False,
        )