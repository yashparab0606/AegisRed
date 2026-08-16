# ============================================================
# AegisRed - Finding Aggregator
# ============================================================

import json
from pathlib import Path
from datetime import datetime, timezone


SEVERITY_SCORE = {
    "None": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


class FindingAggregator:

    def __init__(self, assessment_results):
        self.assessment = assessment_results

    # ========================================================
    # BUILD FINDINGS
    # ========================================================

    def build_findings(self):

        findings = []

        results = self.assessment.get(
            "results",
            [],
        )

        finding_id = 1

        for category_result in results:

            category = category_result.get(
                "category",
                "Unknown",
            )

            attempts = category_result.get(
                "attempts",
                [],
            )

            # ------------------------------------------------
            # Look through every attempt.
            # ------------------------------------------------

            for attempt_record in attempts:

                analysis = attempt_record.get(
                    "analysis",
                    {},
                )

                vulnerable = analysis.get(
                    "vulnerable",
                    False,
                )

                attack_success = analysis.get(
                    "attack_success",
                    False,
                )

                outcome = analysis.get(
                    "outcome",
                    "",
                )

                # ------------------------------------------------
                # Only confirmed exploitation becomes a finding.
                #
                # ATTEMPTED is retained in assessment history,
                # but is not treated as a confirmed finding.
                # ------------------------------------------------

                if not (
                    vulnerable
                    and attack_success
                    and outcome == "EXPLOITED"
                ):
                    continue

                finding = {
                    "finding_id": f"AEGISRED-{finding_id:03d}",

                    "status": "CONFIRMED",

                    # ----------------------------------------------------
                    # Classification
                    # ----------------------------------------------------

                    "category": category,

                    "vulnerability_type": (
                        analysis.get(
                            "vulnerability_type",
                            "Unknown",
                        )
                    ),

                    "severity": (
                        analysis.get(
                            "severity",
                            "None",
                        )
                    ),

                    "confidence": (
                        analysis.get(
                            "confidence",
                            0.0,
                        )
                    ),

                    # ----------------------------------------------------
                    # Attack information
                    # ----------------------------------------------------

                    "successful_attempt": (
                        attempt_record.get(
                            "attempt"
                        )
                    ),

                    "attack": (
                        attempt_record.get(
                            "attack",
                            "",
                        )
                    ),

                    "attack_methodology": (
                        self._build_attack_methodology(
                            category=category,
                            attack=attempt_record.get(
                                "attack",
                                "",
                            ),
                        )
                    ),

                    # ----------------------------------------------------
                    # Target evidence
                    # ----------------------------------------------------

                    "target_response": (
                        attempt_record.get(
                            "response",
                            "",
                        )
                    ),

                    "evidence": (
                        analysis.get(
                            "evidence",
                            "",
                        )
                    ),

                    "indicators": (
                        analysis.get(
                            "indicators",
                            [],
                        )
                    ),

                    "reason": (
                        analysis.get(
                            "reason",
                            "",
                        )
                    ),

                    # ----------------------------------------------------
                    # Security assessment information
                    # ----------------------------------------------------

                    "description": (
                        self._build_description(
                            category=category,
                            vulnerability_type=analysis.get(
                                "vulnerability_type",
                                "Unknown",
                            ),
                            reason=analysis.get(
                                "reason",
                                "",
                            ),
                        )
                    ),

                    "impact": (
                        self._build_impact(
                            severity=analysis.get(
                                "severity",
                                "None",
                            ),
                            category=category,
                            vulnerability_type=analysis.get(
                                "vulnerability_type",
                                "Unknown",
                            ),
                            evidence=analysis.get(
                                "evidence",
                                "",
                            ),
                        )
                    ),

                    "reproduction": (
                        self._build_reproduction(
                            target=self.assessment.get(
                                "target",
                                "Unknown",
                            ),
                            category=category,
                            attack=attempt_record.get(
                                "attack",
                                "",
                            ),
                            attempt=attempt_record.get(
                                "attempt",
                            ),
                        )
                    ),

                    "remediation": (
                        self._build_remediation(
                            category=category,
                            vulnerability_type=analysis.get(
                                "vulnerability_type",
                                "Unknown",
                            ),
                        )
                    ),
                }

                findings.append(
                    finding
                )

                finding_id += 1

        return findings

    # ========================================================
    # CATEGORY SUMMARY
    # ========================================================

    def build_category_summary(self):

        summary = []

        results = self.assessment.get(
            "results",
            [],
        )

        for result in results:

            attempts = result.get(
                "attempts",
                [],
            )

            exploited = []

            attempted = []

            blocked = []

            for item in attempts:

                analysis = item.get(
                    "analysis",
                    {},
                )

                outcome = analysis.get(
                    "outcome",
                    "BLOCKED",
                )

                if outcome == "EXPLOITED":

                    exploited.append(
                        item
                    )

                elif outcome == "ATTEMPTED":

                    attempted.append(
                        item
                    )

                else:

                    blocked.append(
                        item
                    )

            summary.append(
                {
                    "category": result.get(
                        "category"
                    ),

                    "total_attempts": len(
                        attempts
                    ),

                    "exploited_attempts": len(
                        exploited
                    ),

                    "attempted_attempts": len(
                        attempted
                    ),

                    "blocked_attempts": len(
                        blocked
                    ),

                    "exploited": bool(
                        exploited
                    ),
                }
            )

        return summary

    # ========================================================
    # RISK SUMMARY
    # ========================================================

    def calculate_risk(self, findings):

        if not findings:

            return {
                "overall_severity": "None",
                "risk_score": 0,
                "finding_count": 0,
            }

        highest_score = 0

        for finding in findings:

            severity = finding.get(
                "severity",
                "None",
            )

            score = SEVERITY_SCORE.get(
                severity,
                0,
            )

            highest_score = max(
                highest_score,
                score,
            )

        reverse_severity = {
            0: "None",
            1: "Low",
            2: "Medium",
            3: "High",
            4: "Critical",
        }

        return {
            "overall_severity": (
                reverse_severity[
                    highest_score
                ]
            ),

            "risk_score": highest_score,

            "finding_count": len(
                findings
            ),
        }

    def _build_description(
        self,
        category,
        vulnerability_type,
        reason,
    ):
        """
        Build a concise description of the confirmed
        vulnerability from the assessment evidence.
        """

        if reason:

            return (
                f"The assessment identified a confirmed "
                f"{vulnerability_type} vulnerability in the "
                f"{category} attack category. "
                f"{reason}"
            )

        return (
            f"The target demonstrated a confirmed "
            f"{vulnerability_type} vulnerability through "
            f"a {category} attack."
        )

    def _build_attack_methodology(
        self,
        category,
        attack,
    ):
        """
        Describe how the attack was performed.
        """

        return (
            f"AegisRed generated a {category} attack using "
            f"the trained offensive attack-generation model. "
            f"The generated payload was submitted to the "
            f"target through the target execution adapter. "
            f"The resulting target behavior was then analyzed "
            f"by the vulnerability-analysis engine."
        )

    
    def _build_impact(
        self,
        severity,
        category,
        vulnerability_type,
        evidence,
    ):
        """
        Describe the potential security impact based on
        the demonstrated vulnerability.
        """

        severity = str(
            severity or "None"
        ).lower()

        category_lower = str(
            category or ""
        ).lower()

        vulnerability_lower = str(
            vulnerability_type or ""
        ).lower()

        evidence_lower = str(
            evidence or ""
        ).lower()

        # ----------------------------------------------------
        # Command execution / tool abuse
        # ----------------------------------------------------

        if (
            "command" in vulnerability_lower
            or "remote code" in vulnerability_lower
            or "tool abuse" in category_lower
            or "excessive agency" in category_lower
            or "command executed" in evidence_lower
        ):

            return (
                "Successful exploitation may allow an "
                "attacker to cause the target agent to perform "
                "unauthorized operations using its available "
                "capabilities. Where privileged command "
                "execution is demonstrated, the impact may "
                "extend to compromise of the underlying "
                "execution environment and disclosure of "
                "protected resources."
            )

        # ----------------------------------------------------
        # System prompt extraction
        # ----------------------------------------------------

        if (
            "system prompt" in category_lower
            or "system prompt" in vulnerability_lower
        ):

            return (
                "Successful exploitation may disclose hidden "
                "instructions or internal configuration that "
                "could help an attacker understand or bypass "
                "the target's intended security controls."
            )

        # ----------------------------------------------------
        # Sensitive information
        # ----------------------------------------------------

        if (
            "sensitive" in category_lower
            or "disclosure" in vulnerability_lower
        ):

            return (
                "Successful exploitation may expose protected "
                "or internal information to an unauthorized "
                "attacker. The impact depends on the sensitivity "
                "and scope of the disclosed information."
            )

        # ----------------------------------------------------
        # Indirect prompt injection
        # ----------------------------------------------------

        if (
            "indirect" in category_lower
        ):

            return (
                "Successful exploitation may allow attacker-"
                "controlled external content to influence agent "
                "behavior, potentially causing unauthorized "
                "actions or information disclosure."
            )

        # ----------------------------------------------------
        # Generic prompt injection
        # ----------------------------------------------------

        if (
            "prompt injection" in category_lower
            or "prompt injection" in vulnerability_lower
        ):

            return (
                "Successful exploitation demonstrates that "
                "attacker-controlled instructions can influence "
                "the target beyond its intended security "
                "constraints. Depending on the target's "
                "capabilities, this may lead to unauthorized "
                "actions, information disclosure, or further "
                "system compromise."
            )

        # ----------------------------------------------------
        # Fallback
        # ----------------------------------------------------

        return (
            f"The confirmed {severity}-severity vulnerability "
            f"may allow unauthorized behavior associated with "
            f"the {category} attack category."
        )

    def _build_reproduction(
        self,
        target,
        category,
        attack,
        attempt,
    ):
        """
        Generate reproducible assessment steps.
        """

        return [
            f"Select the target: {target}.",

            (
                f"Run the {category} security test "
                f"through the AegisRed assessment pipeline."
            ),

            (
                f"Use the generated attack payload from "
                f"attempt {attempt}."
            ),

            "Submit the payload to the target through "
            "the configured execution adapter.",

            (
                "Capture the resulting target response "
                "and execution evidence."
            ),

            (
                "Verify the observed behavior against the "
                "Gemini vulnerability analysis."
            ),

            (
                "The vulnerability is confirmed when the "
                "assessment records the outcome as EXPLOITED "
                "with attack_success=true and vulnerable=true."
            ),
        ]

    def _build_remediation(
        self,
        category,
        vulnerability_type,
    ):
        """
        Provide category-specific defensive recommendations.
        """

        category_lower = str(
            category or ""
        ).lower()

        vulnerability_lower = str(
            vulnerability_type or ""
        ).lower()

        # ----------------------------------------------------
        # Tool abuse / excessive agency
        # ----------------------------------------------------

        if (
            "tool abuse" in category_lower
            or "excessive agency" in category_lower
            or "command" in vulnerability_lower
            or "remote code" in vulnerability_lower
        ):

            return [
                "Apply least-privilege permissions to agent tools.",

                "Require explicit authorization before "
                "high-impact tool operations.",

                "Sandbox command execution and isolate the "
                "agent from sensitive host resources.",

                "Prevent access to protected system files and "
                "credentials.",

                "Validate and constrain tool arguments before "
                "execution.",

                "Log and monitor security-sensitive tool calls.",
            ]

        # ----------------------------------------------------
        # System prompt extraction
        # ----------------------------------------------------

        if (
            "system prompt" in category_lower
            or "system prompt" in vulnerability_lower
        ):

            return [
                "Do not expose system prompts or hidden "
                "instructions to untrusted users.",

                "Separate privileged configuration from "
                "user-visible model context.",

                "Add controls against direct and indirect "
                "instruction-extraction attempts.",

                "Treat system instructions as confidential "
                "security-sensitive information.",
            ]

        # ----------------------------------------------------
        # Sensitive information
        # ----------------------------------------------------

        if (
            "sensitive" in category_lower
            or "disclosure" in vulnerability_lower
        ):

            return [
                "Apply strict access controls to sensitive data.",

                "Do not provide protected information solely "
                "because it is requested through natural language.",

                "Redact secrets, credentials, tokens, and other "
                "sensitive values from model responses.",

                "Apply least privilege to data-accessing tools.",

                "Log and monitor sensitive-data access.",
            ]

        # ----------------------------------------------------
        # Indirect prompt injection
        # ----------------------------------------------------

        if (
            "indirect" in category_lower
        ):

            return [
                "Treat external and retrieved content as "
                "untrusted data.",

                "Separate instructions from untrusted content.",

                "Do not allow retrieved text to directly "
                "override higher-priority instructions.",

                "Require authorization before externally "
                "influenced actions are executed.",

                "Monitor retrieved content and downstream "
                "tool calls for injection indicators.",
            ]

        # ----------------------------------------------------
        # Prompt injection
        # ----------------------------------------------------

        if (
            "prompt injection" in category_lower
            or "prompt injection" in vulnerability_lower
        ):

            return [
                "Enforce a strict instruction hierarchy.",

                "Treat user-controlled instructions as "
                "untrusted input.",

                "Prevent untrusted prompts from directly "
                "overriding security policies.",

                "Require authorization for sensitive actions.",

                "Apply least privilege to all tools available "
                "to the agent.",

                "Monitor and log attempts to bypass agent "
                "security controls.",
            ]

        # ----------------------------------------------------
        # Generic
        # ----------------------------------------------------

        return [
            "Apply least-privilege access controls.",

            "Validate untrusted input before processing.",

            "Require authorization for security-sensitive "
            "operations.",

            "Monitor and log suspicious agent behavior.",

            "Add regression tests for the confirmed attack.",
        ]


    # ========================================================
    # COMPLETE AGGREGATION
    # ========================================================

    def aggregate(self):

        findings = (
            self.build_findings()
        )

        category_summary = (
            self.build_category_summary()
        )

        risk = (
            self.calculate_risk(
                findings
            )
        )

        total_attempts = (
            self.assessment.get(
                "total_attempts",
                0,
            )
        )

        exploited_categories = sum(
            1
            for item in category_summary
            if item["exploited"]
        )

        return {
            "report_metadata": {
                "generated_at": (
                    datetime.now(timezone.utc)
                    .isoformat()
                    + "Z"
                ),

                "target": (
                    self.assessment.get(
                        "target"
                    )
                ),

                "protocol": (
                    self.assessment.get(
                        "protocol"
                    )
                ),

                "analyzer": (
                    self.assessment.get(
                        "analyzer",
                        {}
                    )
                ),
            },

            "assessment_summary": {
                "categories_assessed": (
                    len(
                        category_summary
                    )
                ),

                "total_attempts": (
                    total_attempts
                ),

                "exploited_categories": (
                    exploited_categories
                ),

                "confirmed_findings": (
                    len(findings)
                ),
            },

            "risk_summary": risk,

            "category_summary": (
                category_summary
            ),

            "findings": findings,
        }


# ============================================================
# FILE HELPER
# ============================================================

def load_assessment(path):

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"Assessment file not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


def aggregate_file(
    input_file,
    output_file="aggregated_findings.json",
):

    assessment = load_assessment(
        input_file
    )

    aggregator = (
        FindingAggregator(
            assessment
        )
    )

    report = (
        aggregator.aggregate()
    )

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return report


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    INPUT = (
        "gemini_adaptive_assessment_results.json"
    )

    OUTPUT = (
        "aggregated_findings.json"
    )

    print(
        "=" * 70
    )

    print(
        "AEGISRED - FINDING AGGREGATOR"
    )

    print(
        "=" * 70
    )

    report = aggregate_file(
        INPUT,
        OUTPUT,
    )

    print(
        "\nTarget:"
    )

    print(
        report[
            "report_metadata"
        ][
            "target"
        ]
    )

    print(
        "\nConfirmed findings:"
    )

    print(
        report[
            "assessment_summary"
        ][
            "confirmed_findings"
        ]
    )

    print(
        "\nOverall severity:"
    )

    print(
        report[
            "risk_summary"
        ][
            "overall_severity"
        ]
    )

    print(
        "\nFindings:"
    )

    for finding in report[
        "findings"
    ]:

        print(
            f"\n{finding['finding_id']}"
        )

        print(
            f"  Category : "
            f"{finding['category']}"
        )

        print(
            f"  Type     : "
            f"{finding['vulnerability_type']}"
        )

        print(
            f"  Severity : "
            f"{finding['severity']}"
        )

        print(
            f"  Attempt  : "
            f"{finding['successful_attempt']}"
        )

    print(
        "\n[PASS] Aggregation completed."
    )

    print(
        f"[PASS] Saved: {OUTPUT}"
    )