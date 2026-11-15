
import os
import joblib
import numpy as np
import pandas as pd
import tldextract

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ---------------------------------------
# 1. FILE PATHS
# ---------------------------------------

ORIGINAL_DATA = "data/phishing_url_dataset_unique.csv"
EXTRA_DATA = "data/extra_urls.csv"
MANUAL_TEST = "data/manual_tests.csv"

MODEL_DIR = "model"
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishguard_model.joblib"
)

os.makedirs(MODEL_DIR, exist_ok=True)

# Use bundled public suffix information.
extract_domain = tldextract.TLDExtract(
    suffix_list_urls=[]
)

# ---------------------------------------
# 2. DOMAIN EXTRACTION
# ---------------------------------------

def get_domain(url):

    try:
        result = extract_domain(url)

        if result.domain and result.suffix:
            return (
                result.domain + "." + result.suffix
            ).lower()

        if result.domain:
            return result.domain.lower()

        return "unknown"

    except Exception:
        return "unknown"


# ---------------------------------------
# 3. LOAD DATASETS
# ---------------------------------------

print("\nLoading datasets...")

if not os.path.exists(ORIGINAL_DATA):
    raise FileNotFoundError(
        "Original dataset not found."
    )

original = pd.read_csv(ORIGINAL_DATA)

datasets = [original]

if os.path.exists(EXTRA_DATA):

    extra = pd.read_csv(EXTRA_DATA)

    datasets.append(extra)

    print("Additional dataset loaded.")

else:
    print("No additional dataset found.")

df = pd.concat(
    datasets,
    ignore_index=True
)

if "url" not in df.columns or "label" not in df.columns:
    raise ValueError(
        "Dataset must contain url and label columns."
    )

print("Combined rows:", len(df))

# ---------------------------------------
# 4. CLEAN DATA
# ---------------------------------------

df["url"] = (
    df["url"]
    .fillna("")
    .astype(str)
    .str.strip()
)

df["label"] = (
    df["label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

label_mapping = {
    "0": 0,
    "1": 1,
    "legitimate": 0,
    "benign": 0,
    "safe": 0,
    "good": 0,
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "spam": 1,
    "bad": 1
}

df["label"] = df["label"].map(label_mapping)

df = df.dropna(subset=["label"])
df = df[df["url"] != ""]

df["label"] = df["label"].astype(int)

# Remove URLs with conflicting labels.

conflicts = (
    df.groupby("url")["label"]
    .nunique()
)

conflicting_urls = conflicts[
    conflicts > 1
].index

print(
    "Conflicting URLs:",
    len(conflicting_urls)
)

df = df[
    ~df["url"].isin(conflicting_urls)
]

df = df.drop_duplicates(
    subset=["url"]
).reset_index(drop=True)

if df["label"].nunique() != 2:
    raise ValueError(
        "Both legitimate and phishing classes are required."
    )

df["url_length"] = df["url"].str.len()

df["domain"] = df["url"].apply(
    get_domain
)

print("\nClean rows:", len(df))

print("\nClass distribution:")
print(
    df["label"].value_counts()
    .rename({
        0: "Legitimate",
        1: "Phishing"
    })
)

# ---------------------------------------
# 5. CHECK LONG URL DATA
# ---------------------------------------

print("\nLong URL distribution:")

for limit in [100, 200]:
    subset = df[
        df["url_length"] >= limit
    ]

    print(
        f"Length >= {limit}:",
        len(subset)
    )

    print(
        subset["label"]
        .value_counts()
        .rename({
            0: "Legitimate",
            1: "Phishing"
        })
    )

# ---------------------------------------
# 6. DOMAIN-BASED SPLIT
# ---------------------------------------

X = df["url"]
y = df["label"]
groups = df["domain"]

splitter = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X, y, groups)
)

X_train = X.iloc[train_indices]
X_test = X.iloc[test_indices]

y_train = y.iloc[train_indices]
y_test = y.iloc[test_indices]

if y_train.nunique() != 2 or y_test.nunique() != 2:
    raise ValueError(
        "Domain split did not contain both classes. "
        "Improve dataset diversity before training."
    )

print("\nTraining rows:", len(X_train))
print("Testing rows:", len(X_test))

train_domains = set(
    groups.iloc[train_indices]
)

test_domains = set(
    groups.iloc[test_indices]
)

print(
    "Overlapping domains:",
    len(train_domains.intersection(test_domains))
)

# ---------------------------------------
# 7. BUILD MODEL
# ---------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=250000,
            min_df=2,
            sublinear_tf=True,
            dtype=np.float32
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])

# ---------------------------------------
# 8. TRAIN
# ---------------------------------------

print("\nTraining PhishGuard AI...")

model.fit(
    X_train,
    y_train
)

print("Training completed.")

# ---------------------------------------
# 9. EVALUATION
# ---------------------------------------

predictions = model.predict(X_test)

print("\n========== PERFORMANCE ==========")

print(
    "Accuracy:",
    round(
        accuracy_score(y_test, predictions) * 100,
        2
    ),
    "%"
)

print(
    "Precision:",
    round(
        precision_score(
            y_test,
            predictions,
            zero_division=0
        ) * 100,
        2
    ),
    "%"
)

print(
    "Recall:",
    round(
        recall_score(
            y_test,
            predictions,
            zero_division=0
        ) * 100,
        2
    ),
    "%"
)

print(
    "F1 Score:",
    round(
        f1_score(
            y_test,
            predictions,
            zero_division=0
        ) * 100,
        2
    ),
    "%"
)

print("\nClassification report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)

print("\nConfusion matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)

# ---------------------------------------
# 10. LONG URL EVALUATION
# ---------------------------------------

results = pd.DataFrame({
    "url": X_test.values,
    "actual": y_test.values,
    "predicted": predictions
})

results["length"] = (
    results["url"].str.len()
)

print("\n========== LONG URL TEST ==========")

for limit in [100, 200]:

    subset = results[
        results["length"] >= limit
    ]

    print(f"\nURL length >= {limit}")
    print("Total:", len(subset))

    if len(subset) == 0:
        print("No examples available.")
        continue

    print(
        "Accuracy:",
        round(
            accuracy_score(
                subset["actual"],
                subset["predicted"]
            ) * 100,
            2
        ),
        "%"
    )

    legitimate = subset[
        subset["actual"] == 0
    ]

    if len(legitimate) > 0:

        false_positives = (
            legitimate["predicted"] == 1
        ).sum()

        print(
            "Legitimate URLs:",
            len(legitimate)
        )

        print(
            "False positives:",
            false_positives
        )

# ---------------------------------------
# 11. MANUAL TESTS
# ---------------------------------------

if os.path.exists(MANUAL_TEST):

    manual = pd.read_csv(MANUAL_TEST)

    print("\n========== MANUAL TESTS ==========")

    if not {"url", "expected_label"}.issubset(
        manual.columns
    ):
        raise ValueError(
            "Manual test file needs url and expected_label."
        )

    manual["expected_label"] = pd.to_numeric(
        manual["expected_label"],
        errors="coerce"
    )

    manual = manual.dropna(
        subset=["expected_label"]
    )

    manual["expected_label"] = (
        manual["expected_label"].astype(int)
    )

    manual = manual[
        manual["expected_label"].isin([0, 1])
    ]

    if len(manual) > 0:

        manual_predictions = model.predict(
            manual["url"].astype(str)
        )

        for index, row in manual.iterrows():

            predicted = int(
                manual_predictions[
                    manual.index.get_loc(index)
                ]
            )

            expected = int(
                row["expected_label"]
            )

            print("\nURL:", row["url"])
            print(
                "Expected:",
                "Legitimate" if expected == 0 else "Phishing"
            )

            print(
                "Predicted:",
                "Legitimate" if predicted == 0 else "Phishing"
            )

            print(
                "Correct:",
                predicted == expected
            )

# ---------------------------------------
# 12. SAVE MODEL
# ---------------------------------------

joblib.dump(
    model,
    MODEL_PATH
)

print("\nModel saved successfully:")
print(MODEL_PATH)
