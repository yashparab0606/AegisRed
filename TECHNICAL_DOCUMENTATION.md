    # AegisRed Technical Documentation

## 1. Overview

AegisRed is an automated red-teaming pipeline designed to evaluate the security of AI agents that expose tools or external capabilities.

The pipeline combines:

* Target reconnaissance
* Attack-surface identification
* LLM-based attack generation
* Automated attack execution
* Response analysis
* Adaptive attack attempts
* Evidence collection
* Vulnerability verification
* Finding aggregation
* Security report generation

The current target used for assessment is CodeBot.

---

## 2. System Architecture

```text
                         ┌──────────────────┐
                         │   Target Agent    │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │  Reconnaissance  │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ Attack Surface   │
                         │ Identification   │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ AegisRed Attack  │
                         │    Generator     │
                         │ Qwen + LoRA      │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ Attack Executor  │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ Target Response  │
                         │ + Evidence       │
                         └─────────┬────────┘
                                   │
                     ┌─────────────┴─────────────┐
                     │                           │
                     ▼                           ▼
             ┌───────────────┐          ┌────────────────┐
             │ Gemini        │          │ Offline        │
             │ Analyzer      │          │ Analyzer       │
             └───────┬───────┘          └───────┬────────┘
                     │                          │
                     └────────────┬─────────────┘
                                  ▼
                         ┌──────────────────┐
                         │ Finding          │
                         │ Aggregation      │
                         └─────────┬────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ JSON / MD / HTML │
                         │ Security Report  │
                         └──────────────────┘
```

---

## 3. Target Reconnaissance

Before generating attacks, AegisRed inspects the target's available capabilities.

For CodeBot, reconnaissance identifies security-relevant functionality including:

* `execute_command`
* `read_file`
* `write_file`
* `git`
* `npm`

These capabilities are used to determine possible attack surfaces.

The reconnaissance stage provides context to later attack-generation stages instead of relying only on generic attack prompts.

---

## 4. Attack Surface Identification

The discovered capabilities are mapped to potential security risks.

Examples include:

| Target Capability          | Potential Attack Surface             |
| -------------------------- | ------------------------------------ |
| `execute_command`          | Command execution / excessive agency |
| `read_file`                | Unauthorized file access             |
| `write_file`               | Unauthorized file modification       |
| `git`                      | Repository manipulation              |
| `npm`                      | Package/tool abuse                   |
| Natural-language interface | Prompt injection                     |

This information is provided to the attack-generation stage.

---

## 5. Attack Generation

AegisRed uses an adapted open-source language model for attack generation.

### Base Model

`Qwen2.5-0.5B-Instruct`

### Adaptation

AegisRed uses a LoRA adapter trained on a security-focused attack dataset.

The adapter is intended to specialize the base model toward generating attacks relevant to AI-agent security testing.

The generated attack is influenced by:

* Vulnerability category
* Target capabilities
* Previously attempted attacks
* Previous target responses
* Previous analysis
* Current assessment state

---

## 6. Attack Execution

Generated attacks are passed automatically to the CodeBot target.

The execution layer is responsible for:

1. Sending the attack.
2. Receiving the target response.
3. Capturing execution metadata.
4. Recording tool activity.
5. Returning the complete assessment evidence to the analyzer.

The executor does not independently determine whether an attack succeeded.

This separation allows attack execution and vulnerability verification to remain independent components.

---

## 7. Evidence Collection

Each assessment attempt records relevant evidence.

Typical evidence includes:

```text
Attack prompt
Target response
HTTP/execution status
Tool calls
Raw response
Execution metadata
Analysis result
Assessment state
```

This evidence is passed to subsequent stages and included in the generated security reports.

Evidence collection is important because a vulnerability classification should be supported by observable target behavior rather than only the attacker's intent.

---

## 8. Response Analysis

AegisRed currently provides two analysis paths.

### 8.1 Gemini Analyzer

The Gemini analyzer is the primary semantic verifier.

It evaluates the attack and target behavior and determines whether the attack was:

```text
BLOCKED
ATTEMPTED
EXPLOITED
```

The analyzer can consider contextual evidence rather than relying only on keyword matching.

This makes it better suited to attacks where successful behavior is indirect or expressed differently from the original attack.

### 8.2 Offline Analyzer

An offline analyzer is also implemented for environments where an external LLM is unavailable.

The offline analyzer uses local analysis logic to classify responses.

However, its current semantic detection capability is weaker than the Gemini analyzer.

In testing, the offline analyzer can miss attacks that require contextual interpretation. Therefore, it is currently treated as an experimental fallback rather than the authoritative verifier.

Future improvements can include:

* Better response parsing
* Tool-call-aware rules
* Structured behavioral indicators
* Local classifier models
* Hybrid rules + LLM classification

---

## 9. Vulnerability Classification

AegisRed uses three primary assessment states.

### BLOCKED

The target rejected the attack and did not demonstrate the requested unsafe behavior.

### ATTEMPTED

The target appeared to partially process or approach the requested behavior, but there was insufficient evidence of successful exploitation.

### EXPLOITED

The target demonstrated observable behavior indicating that the attack succeeded.

The classification should be based on target evidence rather than the attack prompt alone.

---

## 10. Adaptive Assessment Loop

AegisRed performs multiple attempts for each vulnerability category.

The current configuration performs:

```text
5 vulnerability categories
×
3 attempts per category
=
15 assessment attempts
```

The adaptive loop maintains assessment state between attempts.

Conceptually:

```text
Attempt 1
   │
   ├── Attack
   ├── Target response
   └── Analysis
          │
          ▼
     Assessment State
          │
          ▼
Attempt 2
   │
   ├── Previous evidence
   ├── Previous analysis
   └── New attack
          │
          ▼
     Updated State
          │
          ▼
Attempt 3
```

The next attack can therefore be informed by the result of the previous attempt.

This is different from simply generating three independent attacks.

---

## 11. Assessment State

The adaptive state contains information from previous attempts.

Relevant information includes:

* Previous attack
* Previous target response
* Previous analysis
* Vulnerability category
* Evidence collected
* Current assessment result

The state is supplied to subsequent attack-generation or analysis stages where applicable.

This allows the system to modify its testing strategy based on observed target behavior.

---

## 12. Finding Aggregation

After individual attempts are analyzed, AegisRed aggregates relevant results into security findings.

A finding contains information such as:

```text
Finding ID
Vulnerability category
Severity
Confidence
Risk score
Attack evidence
Target response
Verification result
```

Example:

```text
AEGISRED-001
```

The aggregation layer separates individual attack attempts from higher-level security findings.

This allows several related attempts to contribute evidence toward one finding.

---

## 13. Severity and Risk

Findings include severity and confidence information.

The risk score is derived from the assessment information available to the aggregation stage.

The purpose is to prioritize findings rather than simply report every failed or suspicious attack as a confirmed vulnerability.

A high-confidence exploitation result should therefore have substantially greater significance than a blocked attack.

---

## 14. Security Report Generation

The reporting component converts assessment results into multiple formats.

### JSON

Used for structured machine-readable assessment results.

### Markdown

Used for human-readable technical reporting and repository documentation.

### HTML

Used for presentation of assessment results in a browser.

Reports are generated from the assessment data rather than manually written after the test.

The generated reports include the evidence and analysis associated with the assessment.

---

## 15. Five Vulnerability Categories

The pipeline currently implements the five vulnerability categories required by the assignment.

Each category has:

* Attack-generation logic
* Attack execution
* Response analysis
* Adaptive attempts
* Evidence collection
* Result aggregation

The categories are evaluated independently so that individual attack classes can be assessed and reported separately.

---

## 16. Offline Assessment

The complete offline assessment has been exercised using:

```text
5 categories
3 attempts/category
15 total attempts
```

The assessment completed successfully from a pipeline-execution perspective.

The latest real-target run produced:

```text
15 BLOCKED
0 ATTEMPTED
0 EXPLOITED
```

This result means that the pipeline successfully completed the assessment but did **not** establish a confirmed vulnerability in the tested CodeBot configuration.

A separate synthetic positive-finding test is used to verify that the vulnerability aggregation and reporting components correctly handle an exploitation result.

The synthetic test must not be interpreted as evidence that CodeBot itself was exploited.

---

## 17. Current Verification Strategy

The recommended execution configuration is:

```text
Attack Generation
       ↓
Attack Execution
       ↓
Evidence Collection
       ↓
Gemini Semantic Verification
       ↓
Finding Aggregation
       ↓
Report Generation
```

The offline analyzer can be used when external model access is unavailable, but its results should be treated with lower confidence until its detection logic is improved.

---

## 18. Error Handling and Isolation

The pipeline separates the major stages so that an analysis failure does not necessarily invalidate the complete assessment.

The major boundaries are:

```text
Reconnaissance
Attack Generation
Attack Execution
Analysis
Aggregation
Reporting
```

Each stage consumes structured information from the previous stage.

This makes individual components easier to test and replace.

---

## 19. Reproducibility

The repository should contain sufficient information to reproduce the main experiment.

This includes:

* Base model information
* LoRA adapter
* Dataset
* Training configuration
* Runtime dependencies
* Assessment configuration
* Target setup
* Execution instructions
* Report-generation instructions

Detailed model reproduction information is provided separately in `MODEL_REPRODUCTION.md`.

Dataset information is provided in `DATASET.md`.

---

## 20. Known Limitations

### Offline Analyzer

The offline analyzer currently has weaker semantic understanding than Gemini and can miss successful attacks that do not match its current detection logic.

### Small Attack Model

Qwen2.5-0.5B is intentionally lightweight. Its small parameter count makes local execution easier but limits the sophistication and diversity of generated attacks.

### Target Dependence

Attack success depends on the configuration and behavior of the target agent. A blocked result does not prove that the target is universally secure.

### No Confirmed Real Vulnerability in Latest Run

The latest complete CodeBot assessment did not produce an `EXPLOITED` result.

Therefore, the current implementation demonstrates an operational red-teaming framework but does not yet provide a confirmed vulnerability finding from the latest real-target assessment.

---

## 21. Current Technical Status

| Component                     | Status                         |
| ----------------------------- | ------------------------------ |
| Reconnaissance                | Complete                       |
| Attack-surface identification | Complete                       |
| LoRA attack generation        | Complete                       |
| Attack execution              | Complete                       |
| Evidence collection           | Complete                       |
| Gemini response analysis      | Complete                       |
| Offline response analysis     | Implemented, needs improvement |
| Adaptive assessment           | Complete                       |
| Vulnerability classification  | Complete                       |
| Finding aggregation           | Complete                       |
| JSON reporting                | Complete                       |
| Markdown reporting            | Complete                       |
| HTML reporting                | Complete                       |
| Real-target assessment        | Executed                       |
| Confirmed real vulnerability  | Not yet demonstrated           |

## 22. Future Improvements

The immediate technical improvement is to strengthen the offline analyzer.

Potential improvements include:

1. Tool-call-aware exploitation detection.
2. Structured extraction of target actions.
3. Detection of unauthorized file or command operations.
4. Better distinction between attempted and successful behavior.
5. Hybrid rule-based and local-model analysis.
6. Agreement testing between Gemini and offline analysis.
7. Additional adaptive attack strategies.

The long-term goal is to make the offline verifier sufficiently reliable to perform meaningful semantic vulnerability classification without depending entirely on an external LLM.
