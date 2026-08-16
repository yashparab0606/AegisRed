"""
AegisRed - Offline Adaptive Security Assessment Orchestrator

EXPERIMENTAL / OFFLINE PIPELINE

This file is completely separate from the production
Gemini pipeline.

Pipeline:

    Target Selection
          ↓
    Reconnaissance
          ↓
    Local Qwen + LoRA Attack Generation
          ↓
    Attack Execution
          ↓
    Offline Vulnerability Analysis
          ↓
    Adaptive Feedback
          ↓
    Next Attack
          ↓
    Finding Aggregation
          ↓
    Security Report

IMPORTANT:

    This orchestrator does NOT import or initialize Gemini.

    Production pipeline remains:

        main_orchestrator.py
                ↓
        GeminiVulnerabilityAnalyzer

    Experimental pipeline:

        offline_orchestrator.py
                ↓
        OfflineVulnerabilityAnalyzer
"""

import json
from pathlib import Path
from typing import Any, Dict, List


# ============================================================
# AEGISRED COMPONENTS
# ============================================================

from src.target.main_reconnaissance import (
    select_target,
    run_api_reconnaissance,
    display_reconnaissance,
)

from src.attack_generator.main_attack_generation import (
    MainAttackGenerator,
    ATTACK_CATEGORIES,
)

from src.executor.main_attack_execution import (
    MainAttackExecutor,
)

from src.analyzer.offline_vulnerability_analyzer import (
    OfflineVulnerabilityAnalyzer,
)

from src.reporting.finding_aggregator import (
    FindingAggregator,
)

from src.reporting.security_report import (
    SecurityReportGenerator,
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_ATTEMPTS_PER_CATEGORY = 3

OFFLINE_RESULT_FILE = (
    "offline_adaptive_assessment_results.json"
)

OFFLINE_AGGREGATED_FILE = (
    "offline_aggregated_findings.json"
)


# ============================================================
# ORCHESTRATOR
# ============================================================

class OfflineAegisRedOrchestrator:
    """
    Coordinates the complete offline AegisRed assessment.

    This class intentionally duplicates only the orchestration
    flow. It does not duplicate:

        - target selection logic
        - reconnaissance logic
        - attack generation logic
        - attack execution logic
        - vulnerability analysis logic
        - aggregation logic
        - report generation logic

    Those remain in their respective modules.
    """

    def __init__(
        self,
        max_attempts: int = MAX_ATTEMPTS_PER_CATEGORY,
    ):

        self.max_attempts = max_attempts

        self.target = None

        self.adapter = None

        self.recon = None

        self.attack_generator = None

        self.attack_executor = None

        self.offline_analyzer = None

        # One result per category.
        #
        # {
        #     "category": "...",
        #     "attempts": [...]
        # }

        self.results: List[
            Dict[str, Any]
        ] = []

    # ========================================================
    # TARGET HELPERS
    # ========================================================

    def _target_name(
        self,
    ) -> str:
        """
        Return the selected target name.
        """

        if isinstance(
            self.target,
            dict,
        ):

            return str(
                self.target.get(
                    "name",
                    self.target.get(
                        "agent_name",
                        "Unknown",
                    ),
                )
            )

        return str(
            getattr(
                self.target,
                "name",
                "Unknown",
            )
        )

    # --------------------------------------------------------

    def _target_protocol(
        self,
    ) -> str:
        """
        Return the selected target protocol.
        """

        if isinstance(
            self.target,
            dict,
        ):

            return str(
                self.target.get(
                    "protocol",
                    "api",
                )
            )

        return str(
            getattr(
                self.target,
                "protocol",
                "api",
            )
        )

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def initialize(
        self,
    ):

        print()
        print("=" * 70)

        print(
            "AEGISRED - OFFLINE SECURITY ASSESSMENT"
        )

        print("=" * 70)

        # ====================================================
        # TARGET
        # ====================================================

        print()
        print("[1] TARGET SELECTION")
        print()

        self.target = select_target()

        if not self.target:

            raise RuntimeError(
                "No target selected."
            )

        print()
        print(
            f"[+] Target: "
            f"{self._target_name()}"
        )

        print(
            f"[+] Protocol: "
            f"{self._target_protocol()}"
        )

        # ====================================================
        # RECONNAISSANCE
        # ====================================================

        print()
        print("[2] RECONNAISSANCE")
        print()

        self.recon = (
            self._run_reconnaissance()
        )

        # ====================================================
        # ATTACK GENERATOR
        # ====================================================

        print()
        print("[3] ATTACK GENERATOR")

        try:

            self.attack_generator = (
                MainAttackGenerator()
            )

        except Exception as exc:

            raise RuntimeError(
                "Attack generator initialization failed: "
                f"{exc}"
            ) from exc

        print(
            "[PASS] Attack generator initialized."
        )

        # ====================================================
        # ATTACK EXECUTOR
        # ====================================================

        print()
        print("[4] ATTACK EXECUTOR")

        if self.adapter is None:

            raise RuntimeError(
                "Attack executor cannot be initialized "
                "because reconnaissance did not produce "
                "a target adapter."
            )

        try:

            self.attack_executor = (
                MainAttackExecutor(
                    adapter=self.adapter
                )
            )

        except Exception as exc:

            raise RuntimeError(
                "Attack executor initialization failed: "
                f"{exc}"
            ) from exc

        print(
            "[PASS] Attack executor initialized."
        )

        # ====================================================
        # OFFLINE ANALYZER
        # ====================================================

        print()
        print(
            "[5] OFFLINE VULNERABILITY ANALYZER"
        )

        try:

            self.offline_analyzer = (
                OfflineVulnerabilityAnalyzer()
            )

        except Exception as exc:

            raise RuntimeError(
                "Offline analyzer initialization failed: "
                f"{exc}"
            ) from exc

        print(
            "[PASS] Offline analyzer initialized."
        )

        print(
            "[INFO] Gemini API calls: 0"
        )

        print(
            "[INFO] External analyzer API calls: 0"
        )

    # ========================================================
    # RECONNAISSANCE
    # ========================================================

    def _run_reconnaissance(
        self,
    ) -> Dict[str, Any]:
        """
        Run API reconnaissance.

        run_api_reconnaissance() returns:

            adapter, reconnaissance

        The adapter is required by MainAttackExecutor.
        """

        protocol = (
            self._target_protocol()
            .lower()
        )

        if protocol != "api":

            raise RuntimeError(
                "The current offline assessment "
                "pipeline supports API targets only."
            )

        try:

            self.adapter, reconnaissance = (
                run_api_reconnaissance(
                    self.target
                )
            )

        except Exception as exc:

            raise RuntimeError(
                "Reconnaissance failed: "
                f"{exc}"
            ) from exc

        if self.adapter is None:

            raise RuntimeError(
                "Target adapter initialization failed."
            )

        if reconnaissance is None:

            raise RuntimeError(
                "Reconnaissance returned no result."
            )

        if not reconnaissance.get(
            "reachable",
            False,
        ):

            error = reconnaissance.get(
                "error",
                "Target is not reachable.",
            )

            raise RuntimeError(
                error
            )

        print(
            "[PASS] Reconnaissance completed."
        )

        display_reconnaissance(
            reconnaissance
        )

        return reconnaissance

    # ========================================================
    # RUN ONE CATEGORY
    # ========================================================

    def run_category(
        self,
        category: str,
    ) -> Dict[str, Any]:
        """
        Execute the complete adaptive loop for one category.

        Flow:

            Generate
               ↓
            Execute
               ↓
            Offline Analyze
               ↓
            Exploited?
             /       \
           YES        NO
            |          |
           STOP     Feedback
                       |
                  Generate next
        """

        print()
        print("=" * 70)

        print(
            f"CATEGORY: {category}"
        )

        print(
            f"MAX ATTEMPTS: "
            f"{self.max_attempts}"
        )

        print("=" * 70)

        category_attempts = []

        previous_attack = None

        previous_response = None

        previous_analysis = None

        vulnerability_found = False

        successful_attempt = None

        # ====================================================
        # ATTEMPT LOOP
        # ====================================================

        for attempt_number in range(
            1,
            self.max_attempts + 1,
        ):

            print()
            print(
                "#" * 70
            )

            print(
                f"# STARTING ATTEMPT "
                f"{attempt_number}"
            )

            print(
                "#" * 70
            )

            # =================================================
            # GENERATION
            # =================================================

            print()
            print(
                "[+] Generating attack..."
            )

            try:

                attack = (
                    self.attack_generator.generate(

                        category=category,

                        target_name=(
                            self._target_name()
                        ),

                        reconnaissance=(
                            self.recon
                        ),

                        previous_attack=(
                            previous_attack
                        ),

                        previous_response=(
                            previous_response
                        ),

                        previous_analysis=(
                            previous_analysis
                        ),
                    )
                )

            except Exception as exc:

                print()
                print(
                    "[ERROR] Attack generation failed:"
                )

                print(
                    exc
                )

                break

            if not attack:

                print(
                    "[ERROR] Generator returned "
                    "an empty attack."
                )

                break

            attack = str(
                attack
            ).strip()

            if not attack:

                print(
                    "[ERROR] Generated attack is empty."
                )

                break

            print(
                "[PASS] Attack generated."
            )

            # =================================================
            # ADAPTIVE CONTEXT
            # =================================================

            if previous_attack:

                print()
                print(
                    "[ADAPTIVE CONTEXT]"
                )

                print(
                    "Previous attack supplied."
                )

                print(
                    "Previous response supplied."
                )

                print(
                    "Previous offline analysis supplied."
                )

            # =================================================
            # EXECUTION
            # =================================================

            print()
            print(
                "[+] Executing attack..."
            )

            try:

                execution = (
                    self.attack_executor.execute(

                        attack=attack,

                        category=category,

                        attempt=attempt_number,
                    )
                )

            except Exception as exc:

                print()
                print(
                    "[ERROR] Attack execution failed:"
                )

                print(
                    exc
                )

                break

            if not isinstance(
                execution,
                dict,
            ):

                print(
                    "[ERROR] Executor returned "
                    "an invalid result."
                )

                break

            if not execution.get(
                "success",
                False,
            ):

                print(
                    "[FAIL] Attack execution failed."
                )

                print(
                    execution.get(
                        "error",
                        "Unknown execution error.",
                    )
                )

                break

            print(
                "[PASS] Attack executed."
            )

            # =================================================
            # RESPONSE
            # =================================================

            response = str(
                execution.get(
                    "response",
                    "",
                )
            )

            # =================================================
            # OFFLINE ANALYSIS
            # =================================================

            print()
            print(
                "[+] Running offline vulnerability analysis..."
            )

            try:

                analysis = (
                    self.offline_analyzer.analyze(

                        execution_result=(
                            execution
                        ),

                        target=(
                            self._target_name()
                        ),

                        protocol=(
                            self._target_protocol()
                        ),
                    )
                )

            except Exception as exc:

                print()
                print(
                    "[ERROR] Offline analysis failed:"
                )

                print(
                    exc
                )

                break

            # =================================================
            # RESULT CONTRACT CHECK
            # =================================================

            if not hasattr(
                analysis,
                "to_dict",
            ):

                raise RuntimeError(
                    "Offline analyzer returned an "
                    "unexpected result type."
                )

            analysis_dict = (
                analysis.to_dict()
            )

            # Make category available to the
            # FindingAggregator.

            analysis_dict[
                "category"
            ] = category

            # =================================================
            # DISPLAY ATTEMPT
            # =================================================

            self._display_attempt(
                category=category,

                attempt=attempt_number,

                attack=attack,

                execution=execution,

                analysis=analysis_dict,
            )

            # =================================================
            # STORE ATTEMPT
            # =================================================

            attempt_record = {
                "attempt": attempt_number,

                "category": category,

                "attack": attack,

                "response": response,

                "status_code": (
                    execution.get(
                        "status_code"
                    )
                ),

                "tool_calls": (
                    execution.get(
                        "tool_calls",
                        [],
                    )
                ),

                "raw_response": (
                    execution.get(
                        "raw_response",
                        {},
                    )
                ),

                "execution_time_ms": (
                    execution.get(
                        "execution_time_ms"
                    )
                ),

                "analysis": analysis_dict,
            }

            category_attempts.append(
                attempt_record
            )

            # =================================================
            # EXPLOITATION DECISION
            # =================================================

            outcome = str(
                analysis_dict.get(
                    "outcome",
                    "BLOCKED",
                )
            ).upper()

            attack_success = bool(
                analysis_dict.get(
                    "attack_success",
                    False,
                )
            )

            vulnerable = bool(
                analysis_dict.get(
                    "vulnerable",
                    False,
                )
            )

            if (
                outcome == "EXPLOITED"
                and attack_success
                and vulnerable
            ):

                vulnerability_found = True

                successful_attempt = (
                    attempt_number
                )

                print()
                print(
                    "!" * 70
                )

                print(
                    "VULNERABILITY CONFIRMED "
                    "BY OFFLINE ANALYZER"
                )

                print(
                    "!" * 70
                )

                # Stop this category immediately.

                break

            # =================================================
            # ADAPTIVE FEEDBACK
            # =================================================

            if (
                attempt_number
                < self.max_attempts
            ):

                print()
                print(
                    "[+] Building offline adaptive feedback..."
                )

                try:

                    previous_analysis = (
                        self.offline_analyzer
                        .build_adaptive_feedback(

                            attack=attack,

                            response=response,

                            analysis=analysis,
                        )
                    )

                except Exception as exc:

                    print()
                    print(
                        "[ERROR] Offline adaptive feedback "
                        "generation failed:"
                    )

                    print(
                        exc
                    )

                    break

                previous_attack = attack

                previous_response = response

                print(
                    "[PASS] Offline adaptive feedback created."
                )

            else:

                print()
                print(
                    "[STOP] Maximum attempts reached."
                )

        # ====================================================
        # CATEGORY RESULT
        # ====================================================

        result = {
            "category": category,

            "attempts": category_attempts,

            "attempt_count": len(
                category_attempts
            ),

            "vulnerability_found": (
                vulnerability_found
            ),

            "successful_attempt": (
                successful_attempt
            ),
        }

        self.results.append(
            result
        )

        return result

    # ========================================================
    # DISPLAY ATTEMPT
    # ========================================================

    @staticmethod
    def _display_attempt(
        category,
        attempt,
        attack,
        execution,
        analysis,
    ):

        print()
        print("=" * 70)

        print(
            f"ATTEMPT {attempt}"
        )

        print(
            f"CATEGORY: {category}"
        )

        print("=" * 70)

        print()
        print(
            "ATTACK:"
        )

        print(
            "-" * 70
        )

        print(
            attack
        )

        print(
            "-" * 70
        )

        print()
        print(
            "TARGET RESPONSE:"
        )

        print(
            "-" * 70
        )

        print(
            execution.get(
                "response",
                "",
            )
        )

        print(
            "-" * 70
        )

        tool_calls = execution.get(
            "tool_calls",
            [],
        )

        if tool_calls:

            print()
            print(
                "TOOL CALLS:"
            )

            print(
                json.dumps(
                    tool_calls,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            )

        print()
        print(
            "OFFLINE ANALYSIS:"
        )

        print(
            "-" * 70
        )

        print(
            f"Attack Successful : "
            f"{analysis.get('attack_success')}"
        )

        print(
            f"Vulnerable        : "
            f"{analysis.get('vulnerable')}"
        )

        print(
            f"Outcome           : "
            f"{analysis.get('outcome')}"
        )

        print(
            f"Confidence        : "
            f"{analysis.get('confidence')}"
        )

        print(
            f"Severity          : "
            f"{analysis.get('severity')}"
        )

        print(
            f"Vulnerability     : "
            f"{analysis.get('vulnerability_type')}"
        )

        print()
        print(
            "Reason:"
        )

        print(
            analysis.get(
                "reason",
                "",
            )
        )

        print()
        print(
            "Evidence:"
        )

        print(
            analysis.get(
                "evidence",
                "",
            )
        )

        indicators = analysis.get(
            "indicators",
            [],
        )

        if indicators:

            print()
            print(
                "Indicators:"
            )

            for indicator in indicators:

                print(
                    f"    - {indicator}"
                )

    # ========================================================
    # RUN COMPLETE ASSESSMENT
    # ========================================================

    def run_assessment(
        self,
    ):

        self.initialize()

        print()
        print("=" * 70)

        print(
            "STARTING FULL OFFLINE ADAPTIVE ASSESSMENT"
        )

        print("=" * 70)

        categories = list(
            ATTACK_CATEGORIES
        )

        print()
        print(
            f"Categories: "
            f"{len(categories)}"
        )

        print(
            f"Maximum attacks: "
            f"{len(categories) * self.max_attempts}"
        )

        for category in categories:

            self.run_category(
                category
            )

        print()
        print("=" * 70)

        print(
            "ALL ATTACK CATEGORIES COMPLETED"
        )

        print("=" * 70)

        return self.results

    # ========================================================
    # SAVE RAW RESULTS
    # ========================================================

    def save_results(
        self,
        path: str = OFFLINE_RESULT_FILE,
    ):

        assessment = {
            "target": self._target_name(),

            "protocol": self._target_protocol(),

            "analyzer": {
                "type": "offline",
                "model": "deterministic-rules",
            },

            "max_attempts_per_category": (
                self.max_attempts
            ),

            "total_attempts": sum(
                len(
                    result.get(
                        "attempts",
                        [],
                    )
                )
                for result in self.results
            ),

            "results": self.results,
        }

        path = Path(
            path
        )

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                assessment,
                file,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        print()
        print(
            f"[PASS] Offline assessment results "
            f"saved to: {path}"
        )

        return assessment

    # ========================================================
    # AGGREGATION
    # ========================================================

    def generate_aggregated_findings(
        self,
        assessment,
    ):

        aggregator = (
            FindingAggregator(
                assessment
            )
        )

        aggregated = (
            aggregator.aggregate()
        )

        path = Path(
            OFFLINE_AGGREGATED_FILE
        )

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                aggregated,
                file,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        print()
        print(
            f"[PASS] Offline aggregated findings "
            f"saved to: {path}"
        )

        return aggregated

    # ========================================================
    # REPORTING
    # ========================================================

    def generate_security_report(
        self,
        aggregated,
    ):

        generator = SecurityReportGenerator(
            aggregated
        )

        paths = generator.save_reports()

        print()
        print(
            "[PASS] Offline reports generated."
        )

        for key, value in paths.items():

            print(
                f"    {key.upper():10}: {value}"
            )

        return paths


    # ========================================================
    # SUMMARY
    # ========================================================

    def print_summary(
        self,
    ):

        total = sum(
            len(
                category.get(
                    "attempts",
                    [],
                )
            )
            for category in self.results
        )

        exploited = sum(
            1
            for category in self.results
            for attempt in category.get(
                "attempts",
                [],
            )
            if attempt.get(
                "analysis",
                {},
            ).get(
                "outcome"
            ) == "EXPLOITED"
        )

        attempted = sum(
            1
            for category in self.results
            for attempt in category.get(
                "attempts",
                [],
            )
            if attempt.get(
                "analysis",
                {},
            ).get(
                "outcome"
            ) == "ATTEMPTED"
        )

        blocked = sum(
            1
            for category in self.results
            for attempt in category.get(
                "attempts",
                [],
            )
            if attempt.get(
                "analysis",
                {},
            ).get(
                "outcome"
            ) == "BLOCKED"
        )

        print()
        print("=" * 70)

        print(
            "FINAL OFFLINE AEGISRED ASSESSMENT SUMMARY"
        )

        print("=" * 70)

        print()

        print(
            f"Target             : "
            f"{self._target_name()}"
        )

        print(
            f"Categories         : "
            f"{len(ATTACK_CATEGORIES)}"
        )

        print(
            f"Total attempts     : "
            f"{total}"
        )

        print(
            f"Exploited          : "
            f"{exploited}"
        )

        print(
            f"Attempted          : "
            f"{attempted}"
        )

        print(
            f"Blocked            : "
            f"{blocked}"
        )

        print()

        print(
            "Analyzer           : "
            "Offline deterministic rules"
        )

        print(
            "Gemini API calls   : 0"
        )

        print()

        print(
            "=" * 70
        )

    # ========================================================
    # COMPLETE PIPELINE
    # ========================================================

    def run(
        self,
    ):

        try:

            # -----------------------------------------------
            # Assessment
            # -----------------------------------------------

            self.run_assessment()

            # -----------------------------------------------
            # Raw results
            # -----------------------------------------------

            assessment = (
                self.save_results()
            )

            # -----------------------------------------------
            # Aggregation
            # -----------------------------------------------

            aggregated = (
                self.generate_aggregated_findings(
                    assessment
                )
            )

            # -----------------------------------------------
            # Reporting
            # -----------------------------------------------

            self.generate_security_report(
                aggregated
            )

            # -----------------------------------------------
            # Summary
            # -----------------------------------------------

            self.print_summary()

            print()
            print("=" * 70)

            print(
                "AEGISRED OFFLINE ASSESSMENT COMPLETED"
            )

            print("=" * 70)

            return True

        except KeyboardInterrupt:

            print()
            print(
                "[STOP] Offline assessment interrupted."
            )

            return False

        except Exception as exc:

            print()
            print("=" * 70)

            print(
                "[ERROR] Offline AegisRed assessment failed."
            )

            print(
                f"[ERROR] {exc}"
            )

            print("=" * 70)

            raise


# ============================================================
# MAIN
# ============================================================

def main():

    orchestrator = (
        OfflineAegisRedOrchestrator(
            max_attempts=MAX_ATTEMPTS_PER_CATEGORY
        )
    )

    orchestrator.run()


if __name__ == "__main__":

    main()