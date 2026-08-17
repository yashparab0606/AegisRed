# AegisRed

AegisRed is an automated red-teaming pipeline for evaluating the
security of AI agents and tool-using AI systems.

It combines a custom offensive attack-generation model with target
reconnaissance, automated attack execution, LLM-based vulnerability
verification, adaptive assessment, evidence collection, finding
aggregation, and security report generation.

## Objective

AegisRed is designed to automatically test whether an AI agent can be
manipulated into:

-   Bypassing security boundaries
-   Disclosing sensitive information
-   Revealing system instructions
-   Performing unsafe tool operations
-   Following malicious or indirect instructions

## Architecture

``` text
Target Agent
     ↓
Reconnaissance
     ↓
Attack-Surface Identification
     ↓
Qwen2.5-0.5B + AegisRed LoRA
     ↓
Attack Execution
     ↓
Target Response + Evidence
     ↓
Gemini Vulnerability Analysis
     ↓
BLOCKED / ATTEMPTED / EXPLOITED
     ↓
Finding Aggregation
     ↓
JSON / Markdown / HTML Reports
```

## Main Components

### Target Reconnaissance

Identifies the capabilities exposed by the target agent, such as command
execution, file access, and other tools.

### Attack Generation

Uses **Qwen2.5-0.5B-Instruct** with the **AegisRed LoRA adapter**,
trained on a security-focused attack dataset.

The generator uses the vulnerability category, target capabilities, and
previous assessment context to generate attacks.

### Attack Execution

Automatically submits generated attacks to the target and records the
target response and execution evidence.

### Vulnerability Analysis

Gemini is used as the primary semantic verifier to determine whether an
attack was:

-   `BLOCKED`
-   `ATTEMPTED`
-   `EXPLOITED`

An offline analyzer is also implemented as a lightweight fallback.

### Adaptive Assessment

Multiple attempts can use information from previous attacks, responses,
and analysis so that subsequent attacks can adapt to observed target
behavior.

### Finding Aggregation

Verified results are converted into structured findings containing
severity, confidence, evidence, and remediation information.

### Reporting

Assessment results are automatically exported as:

-   JSON
-   Markdown
-   HTML

## Vulnerability Categories

The current implementation covers five categories:

1.  Prompt Injection
2.  System Prompt Extraction
3.  Indirect Prompt Injection
4.  Sensitive Information Disclosure
5.  Tool Abuse / Excessive Agency

## Latest Demonstrated Assessment

The latest Gemini-backed assessment used **LegacyBot** as the target.

  Metric                       Result
  -------------------- --------------
  Categories                        5
  Attack attempts                  10
  Blocked                           9
  Exploited                         1
  Confirmed findings                1
  Overall risk           **CRITICAL**

The confirmed finding was classified as **Critical** with **100%
confidence** and demonstrated sensitive information disclosure through
the Tool Abuse / Excessive Agency category.

## Project Structure

```text
AegisRed/
├── data/
├── DEMO/
├── model/
├── notebooks/
├── reports/
├── src/
│   ├── analyzer/
│   ├── attack_generator/
│   ├── executor/
│   ├── orchestrator/
│   ├── reporting/
│   └── target/
├── tests/
├── training/
├── DATASET.md
├── MODEL_REPRODUCTION.md
├── TECHNICAL_DOCUMENTATION.md
├── README.md
├── requirements.txt
└── main.py
```

## Running the Assessment

The general workflow is:

``` text
1. Start the target agent
2. Run reconnaissance
3. Identify the attack surface
4. Load the AegisRed model
5. Generate attacks
6. Execute attacks
7. Analyze responses
8. Perform adaptive attempts
9. Aggregate findings
10. Generate reports
```

Generated reports are stored under the `reports/` directory.

## Gemini API Configuration

AegisRed uses Gemini for semantic vulnerability analysis.

The API key is supplied at runtime and is **not included in the
repository**.

### Windows PowerShell

``` powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

### Linux/macOS

``` bash
export GEMINI_API_KEY="your_api_key_here"
```

Alternatively, create a local `.env` file:

``` text
GEMINI_API_KEY=your_api_key_here
```

Make sure `.env` is included in `.gitignore`.

**Never commit or share the actual API key.**

## Project Status

  Component                       Status
  ------------------------------- ----------
  Open-source offensive model     Complete
  LoRA adaptation                 Complete
  Security attack dataset         Complete
  Target reconnaissance           Complete
  Attack-surface identification   Complete
  Attack generation               Complete
  Attack execution                Complete
  Gemini vulnerability analysis   Complete
  Adaptive assessment             Complete
  Evidence collection             Complete
  Finding aggregation             Complete
  Security reports                Complete
  Demonstration                   Complete

## Limitations

-   The offline analyzer currently has lower semantic detection
    capability than Gemini.
-   Qwen2.5-0.5B is lightweight, which limits the complexity and
    diversity of generated attacks.
-   Results depend on the configuration and behavior of the target being
    assessed.
-   Gemini analysis requires a valid API key and network access.
-   Local inference and assessment runtime depends on the computational
    resources of the development environment; reported timings are not 
    intended as optimized GPU or production performance benchmarks.

## Documentation

For detailed implementation and pipeline behavior, see:

-   `TECHNICAL_DOCUMENTATION.md`
-   `MODEL_REPRODUCTION.md`
-   `DATASET.md`
