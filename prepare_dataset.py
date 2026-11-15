
import pandas as pd
import os

print("Loading downloaded dataset...")

FILE_PATH = "data/phishing_url_dataset.csv"
ORIGINAL_PATH = "data/phishing_url_dataset_unique.csv"
OUTPUT_PATH = "data/extra_urls.csv"

if not os.path.exists(FILE_PATH):
    print("ERROR: downloaded_dataset.csv not found!")
    raise SystemExit

# Load downloaded CSV
try:
    new_data = pd.read_csv(FILE_PATH)
except UnicodeDecodeError:
    new_data = pd.read_csv(FILE_PATH, encoding="latin1")

# Normalize column names
new_data.columns = [
    str(col).strip().lower() for col in new_data.columns
]

print("\nAvailable columns:")
print(new_data.columns.tolist())

# Find URL column
url_candidates = ["url", "urls", "website", "link"]

url_column = next(
    (col for col in url_candidates if col in new_data.columns),
    None
)

# Find label column
label_candidates = ["label", "status", "class", "type", "result"]

label_column = next(
    (col for col in label_candidates if col in new_data.columns),
    None
)

if url_column is None or label_column is None:
    print("\nCould not identify URL or label column.")
    print("Please share the column names printed above.")
    raise SystemExit

# Keep required columns
data = new_data[[url_column, label_column]].copy()
data.columns = ["url", "raw_label"]

# Clean URLs
data["url"] = data["url"].astype(str).str.strip()
data = data[
    data["url"].notna() &
    (data["url"] != "") &
    (data["url"].str.lower() != "nan")
]

# Convert labels
def convert_label(value):
    value = str(value).strip().lower()

    legitimate = [
        "1", "legitimate", "legit", "benign",
        "safe", "good", "0.0"
    ]

    phishing = [
        "0", "phishing", "malicious", "bad",
        "unsafe"
    ]

    if value in legitimate:
        return "Legitimate"

    if value in phishing:
        return "Phishing"

    return None

data["label"] = data["raw_label"].apply(convert_label)

# Stop if unknown labels exist
unknown = data[data["label"].isna()]

if len(unknown) > 0:
    print("\nUnknown labels found:")
    print(unknown["raw_label"].value_counts().head(20))
    print("\nPlease verify label mapping before continuing.")
    raise SystemExit

data = data[["url", "label"]].copy()

# Remove duplicate URLs
data = data.drop_duplicates(subset="url")

# Load original dataset
original = pd.read_csv(ORIGINAL_PATH)

original["url"] = original["url"].astype(str).str.strip()
original["label"] = original["label"].astype(str).str.strip()

# Remove URLs already present in original dataset
original_labels = original.set_index("url")["label"].to_dict()

conflicts = data[
    data.apply(
        lambda row: (
            row["url"] in original_labels and
            original_labels[row["url"]] != row["label"]
        ),
        axis=1
    )
]

print("\nConflicting URLs:", len(conflicts))

data = data[
    ~data["url"].isin(original["url"])
]

# Add source information
data["source"] = "downloaded_dataset"

# Save additional dataset
data.to_csv(OUTPUT_PATH, index=False)

print("\nPREPARATION COMPLETE")
print("--------------------")
print("New URLs:", len(data))
print("\nClass distribution:")
print(data["label"].value_counts())

data["url_length"] = data["url"].str.len()

print("\nLong URL distribution:")
print("100+ characters:")
print(
    data[data["url_length"] >= 100]["label"].value_counts()
)

print("\n200+ characters:")
print(
    data[data["url_length"] >= 200]["label"].value_counts()
)

print("\nSaved:", OUTPUT_PATH)
