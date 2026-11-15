
import pandas as pd
from urllib.parse import urlparse

DATA_PATH = "data/phishing_url_dataset_unique.csv"

df = pd.read_csv(DATA_PATH)

# URL length
df["url_length"] = df["url"].astype(str).str.len()

# Extract hostname
def get_domain(url):
    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        return parsed.hostname or "unknown"
    except Exception:
        return "unknown"

df["domain"] = df["url"].astype(str).apply(get_domain)

print("\n========== DATASET AUDIT ==========")

print("\nDataset size:", len(df))

print("\nSource distribution:")
print(pd.crosstab(df["source"], df["label"]))

print("\nURL length statistics:")
print(df.groupby("label")["url_length"].describe())

print("\nLong legitimate URLs (100+):")
print(
    df[
        (df["label"] == 0) &
        (df["url_length"] >= 100)
    ][["url", "source", "url_length"]]
    .head(20).to_string(index=False)
)

print("\nLong phishing URLs (100+):")
print(
    df[
        (df["label"] == 1) &
        (df["url_length"] >= 100)
    ][["url", "source", "url_length"]]
    .head(20).to_string(index=False)
)

print("\nTop legitimate domains:")
print(
    df[df["label"] == 0]["domain"]
    .value_counts().head(20)
)

print("\nTop phishing domains:")
print(
    df[df["label"] == 1]["domain"]
    .value_counts().head(20)
)

print("\n========== AUDIT COMPLETED ==========")
