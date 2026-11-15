
import pandas as pd
import os

ORIGINAL = "data/phishing_url_dataset_unique.csv"
EXTRA = "data/extra_urls.csv"
NEW_DATA = "data/commoncrawl_dataset.csv"

print("Loading datasets...")

# Load new dataset
new = pd.read_csv(NEW_DATA)

new.columns = [str(c).strip().lower() for c in new.columns]

if not {"url", "label"}.issubset(new.columns):
    raise ValueError("New dataset must contain URL and Label columns.")

new = new[["url", "label"]].copy()

# Convert labels: 0 = Legitimate, 1 = Phishing
new["label"] = pd.to_numeric(new["label"], errors="coerce")
new["label"] = new["label"].map({
    0: "Legitimate",
    1: "Phishing"
})

new["url"] = new["url"].astype(str).str.strip()

new = new[
    new["url"].str.startswith(
        ("http://", "https://"),
        na=False
    )
    & new["label"].notna()
]

new["source"] = "commoncrawl_phishtank"

# Load original dataset
original = pd.read_csv(ORIGINAL)

original.columns = [str(c).strip().lower() for c in original.columns]

original["url"] = original["url"].astype(str).str.strip()
original["label"] = original["label"].astype(str).str.strip()

# Normalize old labels
def normalize_label(value):
    value = str(value).strip().lower()

    if value in ["legitimate", "legit", "benign"]:
        return "Legitimate"

    if value in ["phishing", "malicious"]:
        return "Phishing"

    return None

original["label"] = original["label"].apply(normalize_label)

# Load previous additional dataset if available
if os.path.exists(EXTRA):
    old = pd.read_csv(EXTRA)

    old.columns = [str(c).strip().lower() for c in old.columns]

    old["url"] = old["url"].astype(str).str.strip()
    old["label"] = old["label"].apply(normalize_label)

    if "source" not in old.columns:
        old["source"] = "previous_dataset"

    old = old[["url", "label", "source"]]
    print("Previous extra dataset loaded.")
else:
    old = pd.DataFrame(columns=["url", "label", "source"])

# Combine new and previous extra data
combined = pd.concat(
    [old, new],
    ignore_index=True
)

combined = combined.dropna(subset=["url", "label"])

# Check label conflicts across all datasets
all_data = pd.concat([
    original[["url", "label"]],
    combined[["url", "label"]]
], ignore_index=True)

conflicting_urls = (
    all_data.groupby("url")["label"]
    .nunique()
)

conflicting_urls = conflicting_urls[
    conflicting_urls > 1
].index

print("Conflicting URLs:", len(conflicting_urls))

# Remove conflicting URLs
combined = combined[
    ~combined["url"].isin(conflicting_urls)
]

# Remove URLs already present in original dataset
combined = combined[
    ~combined["url"].isin(original["url"])
]

# Remove duplicate URLs
combined = combined.drop_duplicates(subset="url")

# Save additional dataset
combined.to_csv(EXTRA, index=False)

# Final report
combined["url_length"] = combined["url"].str.len()

print("\nMERGE COMPLETE")
print("-------------------------")
print("Additional URLs:", len(combined))

print("\nClass distribution:")
print(combined["label"].value_counts())

print("\nLong URLs (100+):")
print(
    combined[combined["url_length"] >= 100]
    ["label"].value_counts()
)

print("\nLong URLs (200+):")
print(
    combined[combined["url_length"] >= 200]
    ["label"].value_counts()
)

print("\nSaved successfully:", EXTRA)
