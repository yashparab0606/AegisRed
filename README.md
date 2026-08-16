# AegisRed

AegisRed is an automated red-teaming pipeline for evaluating the security of AI agents and tool-using AI systems.

The system combines an adapted open-source language model for attack generation, automated attack execution, response analysis, vulnerability verification, adaptive attack attempts, and security report generation.

## Objective

The goal of AegisRed is to automatically discover and evaluate security weaknesses in AI agents that have access to tools or external capabilities.

The current target used for evaluation is CodeBot, an AI agent exposing capabilities including:

* `execute_command`
* `read_file`
* `write_file`
* `git`
* `npm`

## System Architecture

```text
                    ┌─────────────────────┐
                    │   Target Recon      │
                    │      CodeBot        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Attack Surface      │
                    │ Identification       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ AegisRed LoRA Model  │
                    │ Qwen2.5-0.5B-Instruct│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Attack Execution     │
                    │      Engine          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Target Response      │
                    │ + Evidence           │
                    └──────────┬──────────┘
                               │
                               ▼
             ┌─────────────────┴─────────────────┐
             │                                   │
             ▼                                   ▼
    ┌──────────────────┐              ┌──────────────────┐
    │ Gemini Analyzer  │              │ Offline Analyzer │
    │ Primary verifier │              │ Experimental     │
    └────────┬─────────┘              └────────┬─────────┘
             │                                 │
             └────────────────┬────────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Finding Aggregation │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ JSON / MD / HTML    │
                    │ Security Reports    │
                    └─────────────────────┘
```

## Main Components

### 1. Target Reconnaissance

AegisRed first identifies the capabilities exposed by the target agent.

For CodeBot, reconnaissance identifies command execution, file operations, package-management capabilities, and other potentially security-sensitive functionality.

### 2. Attack Generation

The AegisRed attack-generation model is based on:

* Qwen2.5-0.5B-Instruct
* AegisRed LoRA adapter
* A security-focused attack-generation dataset

The adapted model generates attacks based on the discovered attack surface and vulnerability category.

### 3. Attack Execution

Generated attacks are automatically submitted to the target.

The executor records:

* Attack prompt
* Target response
* HTTP/execution status
* Tool calls
* Raw response
* Execution metadata

### 4. Response Analysis

The pipeline evaluates whether an attack was:

* `BLOCKED`
* `ATTEMPTED`
* `EXPLOITED`

The Gemini-based analyzer is currently the primary semantic verification mechanism.

An offline analyzer is also included as a lightweight fallback. It currently has lower detection reliability than the Gemini analyzer and is retained for offline experimentation and future improvement.

### 5. Adaptive Assessment

AegisRed performs multiple attempts for each vulnerability category.

The next attempt receives information from the previous attempt, including:

* Previous attack
* Target response
* Previous analysis
* Assessment state

This allows subsequent attacks to adapt based on previous results.

### 6. Finding Aggregation

Verified findings are aggregated into structured security findings containing information such as:

* Finding ID
* Vulnerability category
* Severity
* Confidence
* Risk score
* Evidence
* Attack and target response

Example finding identifier:

`AEGISRED-001`

### 7. Report Generation

Assessment results are exported as:

* JSON
* Markdown
* HTML

Reports contain the evidence collected during the assessment and the resulting vulnerability classifications.

## Vulnerability Categories

The pipeline implements five required security vulnerability classes from the assignment.

Each category is tested independently using multiple attack attempts.

The current offline assessment executes:

```text
5 vulnerability categories
×
3 adaptive attempts
=
15 assessment attempts
```

## Current Assessment Status

The complete assessment pipeline has been executed against CodeBot.

The latest real assessment completed all 15 attempts successfully from an execution perspective. However, the latest run classified all 15 attempts as `BLOCKED`.

Therefore:

* The pipeline is operational.
* Attack generation is operational.
* Attack execution is operational.
* Adaptive state handling is operational.
* Evidence collection is operational.
* Gemini-based analysis is operational.
* Report generation is operational.
* A confirmed real-world vulnerability has **not yet been demonstrated** in the latest assessment.

A synthetic positive-finding test is available to validate the finding aggregation and reporting pipeline, but it must not be presented as a real CodeBot vulnerability.

## Project Structure

The repository contains the following major components:

```text
AegisRed/
│
├── attack generation/
├── attack execution/
├── reconnaissance/
├── analyzers/
├── adaptive assessment/
├── reporting/
├── dataset/
├── training/
├── models/
├── tests/
└── reports/
```

The exact directory structure may vary with the final repository cleanup.

## Running the Assessment

The assessment should be executed using the provided project environment and configuration.

The general workflow is:

```text
1. Start CodeBot
2. Run reconnaissance
3. Identify attack surface
4. Load AegisRed model
5. Generate attacks
6. Execute attacks
7. Analyze responses
8. Run adaptive attempts
9. Aggregate findings
10. Generate reports
```

Generated reports are stored under the assessment report directory.

## Reproducibility

The project provides:

* Attack-generation dataset
* LoRA training configuration
* Model/checkpoint information
* Assessment configuration
* Report-generation pipeline

See `MODEL_REPRODUCTION.md` and `DATASET.md` for details.

## Limitations

The current implementation has several limitations.

### Offline Analysis

The offline analyzer does not yet provide the same semantic accuracy as the Gemini analyzer. In particular, it may fail to recognize attacks that are successful through indirect or context-dependent behavior.

Therefore, the offline analyzer should currently be considered an experimental lightweight verifier rather than the authoritative vulnerability detector.

### Confirmed Vulnerability

The latest complete real-target assessment did not produce a confirmed CodeBot vulnerability.

This means the system demonstrates the red-teaming pipeline and assessment methodology, but the current run does not establish that CodeBot is vulnerable to the tested attacks.

### Model Size

The attack-generation model is based on Qwen2.5-0.5B-Instruct with a LoRA adapter. Its small size makes local execution practical but limits attack-generation capability compared with larger language models.

## Project Status

| Component                    | Status               |
| ---------------------------- | -------------------- |
| Open-source offensive model  | Complete             |
| LoRA adaptation              | Complete             |
| Security attack dataset      | Complete             |
| Target reconnaissance        | Complete             |
| Attack surface discovery     | Complete             |
| Attack generation            | Complete             |
| Attack execution             | Complete             |
| Response analysis            | Complete             |
| Five vulnerability classes   | Complete             |
| Adaptive assessment          | Complete             |
| Evidence collection          | Complete             |
| Finding aggregation          | Complete             |
| Security reports             | Complete             |
| Real-target assessment       | Complete             |
| Confirmed real vulnerability | Not yet demonstrated |
| Technical documentation      | In progress          |
| Dataset packaging            | In progress          |
| Reproduction instructions    | In progress          |
| Demonstration                | In progress          |
| Repository cleanup           | In progress          |


## Gemini API Configuration

AegisRed uses Gemini for semantic vulnerability analysis.

The API key is **not included in the repository**. Each user must provide their own Gemini API key.

### Option 1 — Environment Variable

Set the key before running the pipeline.

**Windows PowerShell:**

```powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

**Linux/macOS:**

```bash
export GEMINI_API_KEY="your_api_key_here"
```

Then run AegisRed normally.

### Option 2 — `.env` File

Create a local `.env` file:

```text
GEMINI_API_KEY=your_api_key_here
```

Make sure `.env` is included in `.gitignore`.

Never commit or share the actual API key.

### Note

The Gemini API is used by the response-analysis component. The API key is supplied at runtime and is not part of the AegisRed source code.

