# AegisRed Model Reproduction

## 1. Overview

AegisRed uses a LoRA-adapted version of:

```text
Qwen/Qwen2.5-0.5B-Instruct
```

The model was fine-tuned using the manually created AegisRed security attack dataset.

Training was performed on **Google Colab using a GPU**, as local hardware was not suitable for efficient model fine-tuning.

The resulting LoRA adapter was then downloaded and integrated into the AegisRed pipeline.

---

## 2. Training Data

The training dataset contains:

* **300 total samples**
* **240 training samples**
* **30 validation samples**
* **30 test samples**

The dataset is stored in JSONL format.

The training set was used for LoRA fine-tuning, while validation and test data were kept separate.

---

## 3. Training Process

The training process was performed in Google Colab.

### Step 1 — Start Google Colab

A Google Colab notebook was created and configured with a GPU runtime.

```text
Google Colab
     ↓
GPU Runtime
```

The GPU was used to make LoRA fine-tuning practical.

### Step 2 — Install Dependencies

The notebook installed the required machine-learning libraries, including the libraries used for:

* Transformers
* PEFT / LoRA
* PyTorch
* Dataset processing

### Step 3 — Load Dataset

The JSONL training and validation files were loaded into the training environment.

```text
train.jsonl       → 240 samples
validation.jsonl  → 30 samples
test.jsonl        → 30 samples
```

### Step 4 — Load Base Model

The base model was loaded:

```text
Qwen/Qwen2.5-0.5B-Instruct
```

The tokenizer associated with the model was also loaded.

### Step 5 — Apply LoRA

Instead of updating the complete model, Low-Rank Adaptation (LoRA) was applied.

This significantly reduces the number of parameters that need to be trained and makes fine-tuning possible on a Colab GPU.

Conceptually:

```text
Qwen2.5-0.5B-Instruct
          +
      LoRA Training
          ↓
   AegisRed Adapter
```

### Step 6 — Fine-Tune

The model was trained using the AegisRed attack-generation dataset.

The objective was to specialize the base instruction model toward generating security-focused adversarial prompts.

The model learns patterns involving:

* Attack categories
* Target types
* Security objectives
* Attack strategies
* Concrete attack prompts

### Step 7 — Save Adapter

After training, the LoRA adapter was saved separately from the base model.

The resulting adapter is used by the AegisRed attack generator.

---

## 4. Local Integration

The trained adapter was downloaded from Colab and placed in the project repository.

The AegisRed generator loads:

```text
Base Model:
Qwen/Qwen2.5-0.5B-Instruct

Adapter:
aegisred-qwen25-0.5b-lora
```

The project code loads the base model first and then attaches the trained LoRA adapter using PEFT.

The model is then used by the attack generator to produce target-specific adversarial prompts.

---

## 5. Inference Flow

After training, the model is used as follows:

```text
Target Reconnaissance
        ↓
Attack Category
        ↓
Target Type
        ↓
Objective + Strategy
        ↓
Target Capabilities
        ↓
Qwen2.5-0.5B-Instruct
        +
AegisRed LoRA
        ↓
Generated Attack
        ↓
Target Agent
```

The generator can also receive target information so that attacks are generated against actual capabilities discovered during reconnaissance.

---

## 6. Reproduction Summary

To reproduce the model:

1. Open the provided Colab training notebook.
2. Enable a GPU runtime.
3. Install the required dependencies.
4. Load the AegisRed JSONL dataset.
5. Load `Qwen/Qwen2.5-0.5B-Instruct`.
6. Configure LoRA/PEFT.
7. Fine-tune using the training dataset.
8. Validate using the validation split.
9. Save the trained LoRA adapter.
10. Download the adapter.
11. Place it under the project's `model/` directory.
12. Load the base model together with the adapter using the AegisRed generator.

The final attack generator uses the trained adapter rather than modifying the original Qwen model.

---

## 7. Output

The final model artifact is the AegisRed LoRA adapter:

```text
model/
└── aegisred-qwen25-0.5b-lora/
```

The base Qwen model remains separate and is loaded together with the adapter during inference.

## 8. Training Environment

| Component          | Value                 |
| ------------------ | --------------------- |
| Training platform  | Google Colab          |
| Hardware           | GPU runtime           |
| Base model         | Qwen2.5-0.5B-Instruct |
| Fine-tuning method | LoRA                  |
| Dataset size       | 300 samples           |
| Training split     | 240 samples           |
| Validation split   | 30 samples            |
| Test split         | 30 samples            |
| Output             | AegisRed LoRA adapter |

## 9. Notes

The LoRA approach was selected because it provides a practical way to adapt the small Qwen model using limited GPU resources while keeping the base model unchanged.

For inference, the adapter can also run on CPU, although GPU execution is preferable for faster generation. The AegisRed implementation automatically selects CUDA when available and otherwise falls back to CPU.
