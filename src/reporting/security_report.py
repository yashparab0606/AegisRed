# ============================================================
# AegisRed - Security Report Generator
# ============================================================
#
# Input:
#     aggregated_findings.json
#
# Output:
#     reports/
#         AEGISRED_<target>_<timestamp>.json
#         AEGISRED_<target>_<timestamp>.md
#         AEGISRED_<target>_<timestamp>.html
#
# ============================================================

import json
import html
import re

from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# REPORT GENERATOR
# ============================================================

class SecurityReportGenerator:

    def __init__(self, aggregated_report):

        self.report = aggregated_report

        self.metadata = (
            aggregated_report.get(
                "report_metadata",
                {},
            )
        )

        self.summary = (
            aggregated_report.get(
                "assessment_summary",
                {},
            )
        )

        self.risk = (
            aggregated_report.get(
                "risk_summary",
                {},
            )
        )

        self.categories = (
            aggregated_report.get(
                "category_summary",
                [],
            )
        )

        self.findings = (
            aggregated_report.get(
                "findings",
                [],
            )
        )

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def _safe_filename(value):

        value = str(value)

        value = re.sub(
            r"[^a-zA-Z0-9_-]+",
            "_",
            value,
        )

        return value.strip("_")

    @staticmethod
    def _severity_text(severity):

        severity = str(
            severity or "None"
        )

        return severity.upper()

    @staticmethod
    def _confidence_percent(confidence):

        try:
            return round(
                float(confidence) * 100,
                1,
            )

        except Exception:

            return 0.0

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    def executive_summary(self):

        target = self.metadata.get(
            "target",
            "Unknown",
        )

        categories = self.summary.get(
            "categories_assessed",
            0,
        )

        attempts = self.summary.get(
            "total_attempts",
            0,
        )

        findings = self.summary.get(
            "confirmed_findings",
            0,
        )

        severity = self.risk.get(
            "overall_severity",
            "None",
        )

        if findings == 0:

            conclusion = (
                "No confirmed vulnerability was "
                "identified during this assessment."
            )

        elif severity == "Critical":

            conclusion = (
                "The assessment identified at least "
                "one critical security vulnerability "
                "requiring immediate attention."
            )

        elif severity == "High":

            conclusion = (
                "The assessment identified significant "
                "security weaknesses requiring remediation."
            )

        else:

            conclusion = (
                "The assessment identified security "
                "findings requiring review and remediation."
            )

        return {
            "target": target,

            "categories": categories,

            "attempts": attempts,

            "findings": findings,

            "severity": severity,

            "conclusion": conclusion,
        }

    # ========================================================
    # MARKDOWN REPORT
    # ========================================================

    def generate_markdown(self):

        target = self.metadata.get(
            "target",
            "Unknown",
        )

        protocol = self.metadata.get(
            "protocol",
            "Unknown",
        )

        analyzer = self.metadata.get(
            "analyzer",
            {},
        )

        analyzer_name = analyzer.get(
            "model",
            analyzer.get(
                "type",
                "Unknown",
            ),
        )

        generated_at = self.metadata.get(
            "generated_at",
            "",
        )

        summary = self.executive_summary()

        lines = []

        # ========================================================
        # HEADER
        # ========================================================

        lines.extend(
            [
                "# AegisRed Security Assessment Report",
                "",
                f"**Target:** {target}",
                "",
                f"**Protocol:** {protocol}",
                "",
                f"**Analyzer:** {analyzer_name}",
                "",
                f"**Generated:** {generated_at}",
                "",
                "---",
                "",
            ]
        )

        # ========================================================
        # OVERALL RISK
        # ========================================================

        lines.extend(
            [
                "## Overall Risk",
                "",
                f"**{summary['severity'].upper()}**",
                "",
                (
                    f"Confirmed findings: "
                    f"**{summary['findings']}**"
                ),
                "",
                (
                    f"Attack attempts: "
                    f"**{summary['attempts']}**"
                ),
                "",
                (
                    f"Categories assessed: "
                    f"**{summary['categories']}**"
                ),
                "",
                summary["conclusion"],
                "",
                "---",
                "",
            ]
        )

        # ========================================================
        # EXECUTIVE SUMMARY
        # ========================================================

        lines.extend(
            [
                "## Executive Summary",
                "",
                (
                    f"AegisRed assessed **{target}** "
                    f"across **{summary['categories']}** "
                    f"attack categories and executed "
                    f"**{summary['attempts']}** attack attempts."
                ),
                "",
                (
                    f"The assessment produced "
                    f"**{summary['findings']} confirmed "
                    f"finding(s)**."
                ),
                "",
                "---",
                "",
            ]
        )

        # ========================================================
        # CATEGORY COVERAGE
        # ========================================================

        lines.extend(
            [
                "## Category Coverage",
                "",
                (
                    "| Category | Attempts | Exploited | "
                    "Attempted | Blocked |"
                ),
                (
                    "|---|---:|---:|---:|---:|"
                ),
            ]
        )

        for category in self.categories:

            lines.append(
                "| "
                + str(
                    category.get(
                        "category",
                        "Unknown",
                    )
                )
                + " | "
                + str(
                    category.get(
                        "total_attempts",
                        0,
                    )
                )
                + " | "
                + str(
                    category.get(
                        "exploited_attempts",
                        0,
                    )
                )
                + " | "
                + str(
                    category.get(
                        "attempted_attempts",
                        0,
                    )
                )
                + " | "
                + str(
                    category.get(
                        "blocked_attempts",
                        0,
                    )
                )
                + " |"
            )

        lines.extend(
            [
                "",
                "---",
                "",
            ]
        )

        # ========================================================
        # CONFIRMED FINDINGS
        # ========================================================

        lines.extend(
            [
                "## Confirmed Findings",
                "",
            ]
        )

        if not self.findings:

            lines.extend(
                [
                    "No confirmed vulnerabilities were "
                    "identified during this assessment.",
                    "",
                ]
            )

        else:

            for finding in self.findings:

                finding_id = finding.get(
                    "finding_id",
                    "UNKNOWN",
                )

                category = finding.get(
                    "category",
                    "Unknown",
                )

                vulnerability_type = (
                    finding.get(
                        "vulnerability_type",
                        "Unknown",
                    )
                )

                severity = finding.get(
                    "severity",
                    "None",
                )

                confidence = (
                    self._confidence_percent(
                        finding.get(
                            "confidence",
                            0,
                        )
                    )
                )

                attempt = finding.get(
                    "successful_attempt",
                    "Unknown",
                )

                description = finding.get(
                    "description",
                    "",
                )

                attack_methodology = (
                    finding.get(
                        "attack_methodology",
                        "",
                    )
                )

                attack = finding.get(
                    "attack",
                    "",
                )

                impact = finding.get(
                    "impact",
                    "",
                )

                reproduction = finding.get(
                    "reproduction",
                    [],
                )

                response = finding.get(
                    "target_response",
                    "",
                )

                evidence = finding.get(
                    "evidence",
                    "",
                )

                reason = finding.get(
                    "reason",
                    "",
                )

                indicators = finding.get(
                    "indicators",
                    [],
                )

                remediation = finding.get(
                    "remediation",
                    [],
                )

                # ------------------------------------------------
                # Finding header
                # ------------------------------------------------

                lines.extend(
                    [
                        f"### {finding_id}",
                        "",
                        f"**Category:** {category}",
                        "",
                        (
                            f"**Vulnerability:** "
                            f"{vulnerability_type}"
                        ),
                        "",
                        (
                            f"**Severity:** "
                            f"**{severity.upper()}**"
                        ),
                        "",
                        (
                            f"**Confidence:** "
                            f"{confidence}%"
                        ),
                        "",
                        (
                            f"**Successful Attempt:** "
                            f"{attempt}"
                        ),
                        "",
                    ]
                )

                # ------------------------------------------------
                # Description
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Description",
                        "",
                        description,
                        "",
                    ]
                )

                # ------------------------------------------------
                # Attack methodology
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Attack Methodology",
                        "",
                        attack_methodology,
                        "",
                    ]
                )

                # ------------------------------------------------
                # Attack payload
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Attack Payload",
                        "",
                        "```text",
                        attack,
                        "```",
                        "",
                    ]
                )

                # ------------------------------------------------
                # Impact
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Impact",
                        "",
                        impact,
                        "",
                    ]
                )

                # ------------------------------------------------
                # Reproduction
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Reproduction",
                        "",
                    ]
                )

                if reproduction:

                    for index, step in enumerate(
                        reproduction,
                        start=1,
                    ):

                        lines.append(
                            f"{index}. {step}"
                        )

                else:

                    lines.append(
                        "No reproduction steps recorded."
                    )

                lines.append("")

                # ------------------------------------------------
                # Target response
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Target Response",
                        "",
                        "```text",
                        response,
                        "```",
                        "",
                    ]
                )

                # ------------------------------------------------
                # Evidence
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Evidence",
                        "",
                        evidence,
                        "",
                    ]
                )

                # ------------------------------------------------
                # Analysis
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Gemini Analysis",
                        "",
                        reason,
                        "",
                    ]
                )

                # ------------------------------------------------
                # Indicators
                # ------------------------------------------------

                if indicators:

                    lines.extend(
                        [
                            "#### Security Indicators",
                            "",
                        ]
                    )

                    for indicator in indicators:

                        lines.append(
                            f"- {indicator}"
                        )

                    lines.append("")

                # ------------------------------------------------
                # Remediation
                # ------------------------------------------------

                lines.extend(
                    [
                        "#### Recommended Remediation",
                        "",
                    ]
                )

                if remediation:

                    for item in remediation:

                        lines.append(
                            f"- {item}"
                        )

                else:

                    lines.append(
                        "No remediation guidance recorded."
                    )

                lines.extend(
                    [
                        "",
                        "---",
                        "",
                    ]
                )

        # ========================================================
        # RISK INTERPRETATION
        # ========================================================

        lines.extend(
            [
                "## Risk Interpretation",
                "",
                (
                    "The overall severity represents the "
                    "highest confirmed vulnerability severity "
                    "identified during the assessment."
                ),
                "",
                "| Severity | Meaning |",
                "|---|---|",
                "| None | No confirmed vulnerability |",
                "| Low | Limited security impact |",
                "| Medium | Meaningful security weakness |",
                "| High | Significant security impact |",
                "| Critical | Severe compromise or high-impact exploitation |",
                "",
                "---",
                "",
            ]
        )

        # ========================================================
        # METHODOLOGY
        # ========================================================

        lines.extend(
            [
                "## Assessment Methodology",
                "",
                "The AegisRed assessment pipeline used:",
                "",
                "1. Target selection",
                "2. API reconnaissance",
                "3. Attack-surface discovery",
                "4. Qwen + AegisRed LoRA attack generation",
                "5. Attack execution",
                "6. Target response capture",
                "7. Gemini vulnerability analysis",
                "8. Adaptive attack feedback",
                "9. Finding aggregation",
                "10. Security report generation",
                "",
                (
                    "A vulnerability is considered confirmed "
                    "when the assessment records the target "
                    "outcome as EXPLOITED and the vulnerability "
                    "analysis confirms successful exploitation."
                ),
                "",
                "---",
                "",
                "## End of Report",
                "",
                "Generated by **AegisRed**.",
            ]
        )

        return "\n".join(
            lines
        )



    # ========================================================
    # HTML REPORT
    # ========================================================
    def generate_html(self):

        target = html.escape(
            str(
                self.metadata.get(
                    "target",
                    "Unknown",
                )
            )
        )

        protocol = html.escape(
            str(
                self.metadata.get(
                    "protocol",
                    "Unknown",
                )
            )
        )

        analyzer = self.metadata.get(
            "analyzer",
            {},
        )

        analyzer_name = html.escape(
            str(
                analyzer.get(
                    "model",
                    analyzer.get(
                        "type",
                        "Unknown",
                    ),
                )
            )
        )

        generated_at = html.escape(
            str(
                self.metadata.get(
                    "generated_at",
                    "",
                )
            )
        )

        summary = self.executive_summary()

        severity = html.escape(
            str(
                summary["severity"]
            )
        )

        # ========================================================
        # CATEGORY ROWS
        # ========================================================

        category_rows = []

        for category in self.categories:

            category_rows.append(
                f"""
                <tr>
                    <td>
                        {html.escape(
                            str(
                                category.get(
                                    "category",
                                    "",
                                )
                            )
                        )}
                    </td>

                    <td>
                        {category.get(
                            "total_attempts",
                            0,
                        )}
                    </td>

                    <td>
                        {category.get(
                            "exploited_attempts",
                            0,
                        )}
                    </td>

                    <td>
                        {category.get(
                            "attempted_attempts",
                            0,
                        )}
                    </td>

                    <td>
                        {category.get(
                            "blocked_attempts",
                            0,
                        )}
                    </td>
                </tr>
                """
            )

        # ========================================================
        # FINDING BLOCKS
        # ========================================================

        finding_blocks = []

        for finding in self.findings:

            finding_id = html.escape(
                str(
                    finding.get(
                        "finding_id",
                        "UNKNOWN",
                    )
                )
            )

            category = html.escape(
                str(
                    finding.get(
                        "category",
                        "Unknown",
                    )
                )
            )

            vulnerability = html.escape(
                str(
                    finding.get(
                        "vulnerability_type",
                        "Unknown",
                    )
                )
            )

            finding_severity = html.escape(
                str(
                    finding.get(
                        "severity",
                        "None",
                    )
                )
            )

            confidence = (
                self._confidence_percent(
                    finding.get(
                        "confidence",
                        0,
                    )
                )
            )

            attempt = html.escape(
                str(
                    finding.get(
                        "successful_attempt",
                        "Unknown",
                    )
                )
            )

            description = html.escape(
                str(
                    finding.get(
                        "description",
                        "",
                    )
                )
            )

            attack_methodology = html.escape(
                str(
                    finding.get(
                        "attack_methodology",
                        "",
                    )
                )
            )

            attack = html.escape(
                str(
                    finding.get(
                        "attack",
                        "",
                    )
                )
            )

            impact = html.escape(
                str(
                    finding.get(
                        "impact",
                        "",
                    )
                )
            )

            response = html.escape(
                str(
                    finding.get(
                        "target_response",
                        "",
                    )
                )
            )

            evidence = html.escape(
                str(
                    finding.get(
                        "evidence",
                        "",
                    )
                )
            )

            reason = html.escape(
                str(
                    finding.get(
                        "reason",
                        "",
                    )
                )
            )

            # ----------------------------------------------------
            # Reproduction
            # ----------------------------------------------------

            reproduction_html = ""

            reproduction = finding.get(
                "reproduction",
                [],
            )

            if reproduction:

                for step in reproduction:

                    reproduction_html += (
                        "<li>"
                        + html.escape(
                            str(step)
                        )
                        + "</li>"
                    )

            else:

                reproduction_html = (
                    "<li>"
                    "No reproduction steps recorded."
                    "</li>"
                )

            # ----------------------------------------------------
            # Indicators
            # ----------------------------------------------------

            indicators_html = ""

            indicators = finding.get(
                "indicators",
                [],
            )

            if indicators:

                for indicator in indicators:

                    indicators_html += (
                        "<li>"
                        + html.escape(
                            str(indicator)
                        )
                        + "</li>"
                    )

            else:

                indicators_html = (
                    "<li>No indicators recorded.</li>"
                )

            # ----------------------------------------------------
            # Remediation
            # ----------------------------------------------------

            remediation_html = ""

            remediation = finding.get(
                "remediation",
                [],
            )

            if remediation:

                for item in remediation:

                    remediation_html += (
                        "<li>"
                        + html.escape(
                            str(item)
                        )
                        + "</li>"
                    )

            else:

                remediation_html = (
                    "<li>"
                    "No remediation guidance recorded."
                    "</li>"
                )

            # ----------------------------------------------------
            # Complete finding
            # ----------------------------------------------------

            finding_blocks.append(
                f"""
                <section class="finding">

                    <h3>
                        {finding_id}
                    </h3>

                    <div class="finding-grid">

                        <div>
                            <strong>
                                Category
                            </strong>

                            <span>
                                {category}
                            </span>
                        </div>

                        <div>
                            <strong>
                                Vulnerability
                            </strong>

                            <span>
                                {vulnerability}
                            </span>
                        </div>

                        <div>
                            <strong>
                                Severity
                            </strong>

                            <span class="severity">
                                {finding_severity}
                            </span>
                        </div>

                        <div>
                            <strong>
                                Confidence
                            </strong>

                            <span>
                                {confidence}%
                            </span>
                        </div>

                        <div>
                            <strong>
                                Successful Attempt
                            </strong>

                            <span>
                                {attempt}
                            </span>
                        </div>

                    </div>


                    <h4>
                        Description
                    </h4>

                    <p>
                        {description}
                    </p>


                    <h4>
                        Attack Methodology
                    </h4>

                    <p>
                        {attack_methodology}
                    </p>


                    <h4>
                        Attack Payload
                    </h4>

                    <pre>{attack}</pre>


                    <h4>
                        Impact
                    </h4>

                    <p>
                        {impact}
                    </p>


                    <h4>
                        Reproduction
                    </h4>

                    <ol>
                        {reproduction_html}
                    </ol>


                    <h4>
                        Target Response
                    </h4>

                    <pre>{response}</pre>


                    <h4>
                        Evidence
                    </h4>

                    <p>
                        {evidence}
                    </p>


                    <h4>
                        Gemini Analysis
                    </h4>

                    <p>
                        {reason}
                    </p>


                    <h4>
                        Security Indicators
                    </h4>

                    <ul>
                        {indicators_html}
                    </ul>


                    <h4>
                        Recommended Remediation
                    </h4>

                    <ul>
                        {remediation_html}
                    </ul>

                </section>
                """
            )

        # ========================================================
        # NO FINDINGS
        # ========================================================

        if not finding_blocks:

            finding_blocks.append(
                """
                <p>
                    No confirmed vulnerabilities were
                    identified during this assessment.
                </p>
                """
            )

        # ========================================================
        # COMPLETE HTML DOCUMENT
        # ========================================================

        return f"""
    <!DOCTYPE html>

    <html lang="en">

    <head>

    <meta charset="UTF-8">

    <meta name="viewport"
        content="width=device-width, initial-scale=1.0">

    <title>
    AegisRed Security Report - {target}
    </title>

    <style>

    * {{
        box-sizing: border-box;
    }}

    body {{

        margin: 0;

        padding: 0;

        font-family:
            Arial,
            Helvetica,
            sans-serif;

        background: #0b1020;

        color: #e5e7eb;

        line-height: 1.6;
    }}

    .container {{

        max-width: 1100px;

        margin: auto;

        padding: 40px 24px;
    }}

    .header {{

        background: #111827;

        border: 1px solid #263247;

        border-radius: 12px;

        padding: 30px;

        margin-bottom: 24px;
    }}

    .header h1 {{

        margin-top: 0;

        font-size: 32px;
    }}

    .meta {{

        color: #9ca3af;

        margin: 6px 0;
    }}

    .risk-card {{

        background: #111827;

        border: 1px solid #263247;

        border-radius: 12px;

        padding: 24px;

        margin-bottom: 24px;
    }}

    .risk-value {{

        font-size: 32px;

        font-weight: bold;
    }}

    .finding {{

        background: #111827;

        border: 1px solid #263247;

        border-radius: 12px;

        padding: 28px;

        margin-bottom: 24px;
    }}

    .finding h3 {{

        margin-top: 0;

        font-size: 24px;
    }}

    .finding-grid {{

        display: grid;

        grid-template-columns:
            repeat(
                auto-fit,
                minmax(180px, 1fr)
            );

        gap: 15px;

        margin-bottom: 24px;
    }}

    .finding-grid div {{

        background: #182235;

        padding: 14px;

        border-radius: 8px;
    }}

    .finding-grid strong {{

        display: block;

        color: #94a3b8;

        font-size: 12px;

        text-transform: uppercase;

        margin-bottom: 5px;
    }}

    .severity {{

        font-weight: bold;
    }}

    pre {{

        background: #050914;

        border: 1px solid #263247;

        border-radius: 8px;

        padding: 16px;

        overflow-x: auto;

        white-space: pre-wrap;

        word-break: break-word;

        color: #d1d5db;
    }}

    table {{

        width: 100%;

        border-collapse: collapse;

        margin: 20px 0;
    }}

    th,
    td {{

        padding: 12px;

        border-bottom:
            1px solid #263247;

        text-align: left;
    }}

    th {{

        color: #94a3b8;
    }}

    .footer {{

        margin-top: 40px;

        color: #64748b;

        text-align: center;
    }}

    </style>

    </head>

    <body>

    <div class="container">

        <div class="header">

            <h1>
                AegisRed Security Assessment
            </h1>

            <div class="meta">
                <strong>Target:</strong>
                {target}
            </div>

            <div class="meta">
                <strong>Protocol:</strong>
                {protocol}
            </div>

            <div class="meta">
                <strong>Analyzer:</strong>
                {analyzer_name}
            </div>

            <div class="meta">
                <strong>Generated:</strong>
                {generated_at}
            </div>

        </div>


        <div class="risk-card">

            <h2>
                Overall Risk
            </h2>

            <div class="risk-value">
                {severity.upper()}
            </div>

            <p>
                Confirmed findings:
                <strong>
                    {summary["findings"]}
                </strong>
            </p>

            <p>
                Attack attempts:
                <strong>
                    {summary["attempts"]}
                </strong>
            </p>

            <p>
                Categories assessed:
                <strong>
                    {summary["categories"]}
                </strong>
            </p>

            <p>
                {html.escape(
                    summary["conclusion"]
                )}
            </p>

        </div>


        <div class="risk-card">

            <h2>
                Category Coverage
            </h2>

            <table>

                <thead>

                    <tr>

                        <th>
                            Category
                        </th>

                        <th>
                            Attempts
                        </th>

                        <th>
                            Exploited
                        </th>

                        <th>
                            Attempted
                        </th>

                        <th>
                            Blocked
                        </th>

                    </tr>

                </thead>

                <tbody>

                    {"".join(category_rows)}

                </tbody>

            </table>

        </div>


        <h2>
            Confirmed Findings
        </h2>

        {"".join(finding_blocks)}


        <div class="footer">

            Generated by AegisRed

        </div>

    </div>

    </body>

    </html>
    """
    # ========================================================
    # WRITE REPORTS
    # ========================================================


    def save_reports(
        self,
        output_directory="reports",
    ):
        """
        Save all reports belonging to one assessment
        inside a single timestamped directory.

        Structure:

            reports/
            └── YYYYMMDD_HHMMSS/
                ├── AEGISRED_<target>.json
                ├── AEGISRED_<target>.md
                └── AEGISRED_<target>.html
        """

        # ----------------------------------------------------
        # Root reports directory
        # ----------------------------------------------------

        reports_root = Path(
            output_directory
        )

        reports_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # Target name
        # ----------------------------------------------------

        target = self._safe_filename(
            self.metadata.get(
                "target",
                "Unknown",
            )
        )

        # ----------------------------------------------------
        # ONE timestamp for the entire assessment
        # ----------------------------------------------------

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        # ----------------------------------------------------
        # Create assessment-specific directory
        # ----------------------------------------------------

        assessment_directory = (
            reports_root / timestamp
        )

        assessment_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # File names
        # ----------------------------------------------------

        base_name = (
            f"AEGISRED_{target}"
        )

        json_path = (
            assessment_directory
            / f"{base_name}.json"
        )

        markdown_path = (
            assessment_directory
            / f"{base_name}.md"
        )

        html_path = (
            assessment_directory
            / f"{base_name}.html"
        )

        # ----------------------------------------------------
        # JSON
        # ----------------------------------------------------

        with open(
            json_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.report,
                file,
                indent=2,
                ensure_ascii=False,
            )

        # ----------------------------------------------------
        # Markdown
        # ----------------------------------------------------

        with open(
            markdown_path,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                self.generate_markdown()
            )

        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        with open(
            html_path,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                self.generate_html()
            )

        # ----------------------------------------------------
        # Return all paths
        # ----------------------------------------------------

        return {
            "directory": str(
                assessment_directory
            ),

            "timestamp": timestamp,

            "json": str(
                json_path
            ),

            "markdown": str(
                markdown_path
            ),

            "html": str(
                html_path
            ),
        }
# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 70
    )

    print(
        "AEGISRED - SECURITY REPORT GENERATOR"
    )

    print(
        "=" * 70
    )

    input_file = (
        "aggregated_findings.json"
    )

    if not Path(
        input_file
    ).exists():

        print(
            f"\n[ERROR] {input_file} not found."
        )

        print(
            "\nRun the finding aggregator first:"
        )

        print(
            "python -m src.reporting.finding_aggregator"
        )

        return

    print(
        f"\n[+] Loading: {input_file}"
    )

    with open(
        input_file,
        "r",
        encoding="utf-8",
    ) as file:

        aggregated = json.load(
            file
        )

    print(
        "[PASS] Aggregated findings loaded."
    )

    generator = (
        SecurityReportGenerator(
            aggregated
        )
    )

    print(
        "\n[+] Generating security reports..."
    )

    paths = generator.save_reports()
    print(
        "\n[PASS] Reports generated:"
    )

    print(
        f"\n    Assessment directory:"
    )

    print(
        f"    {paths['directory']}"
    )

    print(
        "\n    Files:"
    )

    print(
        f"        JSON     : "
        f"{paths['json']}"
    )

    print(
        f"        Markdown : "
        f"{paths['markdown']}"
    )

    print(
        f"        HTML     : "
        f"{paths['html']}"
    )

if __name__ == "__main__":
    main()  