import json
import random
from collections import Counter
from pathlib import Path


# Reproducible split
random.seed(42)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SOURCE_DATASET = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "security_attacks_generated.jsonl"
)

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

TRAIN_FILE = PROCESSED_DIR / "train.jsonl"
VALIDATION_FILE = PROCESSED_DIR / "validation.jsonl"
TEST_FILE = PROCESSED_DIR / "test.jsonl"


CATEGORIES = [
    "prompt_injection",
    "system_prompt_extraction",
    "indirect_prompt_injection",
    "information_disclosure",
    "tool_abuse",
]


def load_dataset():
    """Load and parse the generated JSONL dataset."""

    with SOURCE_DATASET.open("r", encoding="utf-8") as f:
        rows = [
            json.loads(line)
            for line in f
            if line.strip()
        ]

    return rows


def validate_dataset(rows):
    """Validate the raw dataset before splitting."""

    required_fields = {
        "id",
        "category",
        "target_type",
        "objective",
        "attack_strategy",
        "attack_prompt",
        "success_indicators",
        "severity",
    }

    assert len(rows) == 300, (
        f"Expected 300 records, found {len(rows)}"
    )

    assert all(
        required_fields.issubset(row.keys())
        for row in rows
    ), "One or more records are missing required fields."

    ids = [row["id"] for row in rows]

    assert len(ids) == len(set(ids)), (
        "Duplicate IDs detected."
    )

    prompts = [row["attack_prompt"] for row in rows]

    assert len(prompts) == len(set(prompts)), (
        "Duplicate attack prompts detected."
    )

    category_counts = Counter(
        row["category"]
        for row in rows
    )

    assert set(category_counts) == set(CATEGORIES), (
        "Unexpected category detected."
    )

    assert all(
        count == 60
        for count in category_counts.values()
    ), (
        f"Expected 60 records per category: "
        f"{category_counts}"
    )

    print("Raw dataset validation: PASS")
    print(f"Records: {len(rows)}")
    print(f"Categories: {dict(category_counts)}")


def stratified_split(rows):
    """Create an 80/10/10 stratified split by category."""

    grouped = {
        category: []
        for category in CATEGORIES
    }

    for row in rows:
        grouped[row["category"]].append(row)

    train = []
    validation = []
    test = []

    for category in CATEGORIES:

        category_rows = grouped[category]

        random.shuffle(category_rows)

        train.extend(category_rows[:48])
        validation.extend(category_rows[48:54])
        test.extend(category_rows[54:60])

    random.shuffle(train)
    random.shuffle(validation)
    random.shuffle(test)

    return train, validation, test


def write_jsonl(path, rows):
    """Write records to a JSONL file."""

    with path.open("w", encoding="utf-8") as f:

        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )


def print_distribution(name, rows):
    """Print category distribution for a split."""

    counts = Counter(
        row["category"]
        for row in rows
    )

    print(f"\n{name}:")
    print(f"Records: {len(rows)}")

    for category in CATEGORIES:
        print(
            f"  {category}: "
            f"{counts.get(category, 0)}"
        )


def main():

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = load_dataset()

    validate_dataset(rows)

    train, validation, test = stratified_split(rows)

    write_jsonl(TRAIN_FILE, train)
    write_jsonl(VALIDATION_FILE, validation)
    write_jsonl(TEST_FILE, test)

    print_distribution("Training", train)
    print_distribution("Validation", validation)
    print_distribution("Test", test)

    print("\nDataset splitting complete.")
    print(f"Train:      {TRAIN_FILE}")
    print(f"Validation: {VALIDATION_FILE}")
    print(f"Test:       {TEST_FILE}")


if __name__ == "__main__":
    main()