# train_model.py
import pickle
from sklearn.linear_model import LogisticRegression
from feature_extractor import extract_features

# -------------------------------
# TRAINING DATA (INITIAL SEED)
# -------------------------------
TRAINING_DATA = [
    ("XSS vulnerability found", "High"),
    ("SQL injection possible", "High"),
    ("Directory indexing enabled", "Medium"),
    ("Missing X-Frame-Options header", "Low"),
    ("Outdated Apache version detected", "Medium"),
    ("Admin page accessible", "High"),
]

LABEL_MAP = {"Low": 0, "Medium": 1, "High": 2}

X = []
y = []

for title, label in TRAINING_DATA:
    X.append(extract_features(title))
    y.append(LABEL_MAP[label])

# Train model
model = LogisticRegression(max_iter=200)
model.fit(X, y)

# Save model
with open("confidence_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ ML confidence model trained and saved.")
