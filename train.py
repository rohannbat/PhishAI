import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
from features import extract_url_features

# --- CONFIGURATION ---
print("🚀 Initializing Enhanced Training Pipeline...")

# --- DATA GENERATION ---


def generate_synthetic_data():
    """
    Generates a large, diverse dataset of URLs + Simulated HTML features.
    """

    # --- LEGITIMATE SITES ---
    # Top 50 global domains + variations
    legit_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "yahoo.com",
        "wikipedia.org", "zoom.us", "live.com", "reddit.com", "netflix.com",
        "microsoft.com", "instagram.com", "linkedin.com", "office.com", "cnn.com",
        "twitch.tv", "nytimes.com", "dropbox.com", "github.com", "salesforce.com",
        "stackoverflow.com", "spotify.com", "adobe.com", "whatsapp.com", "medium.com",
        "bbc.co.uk", "deakin.edu.au", "rmit.edu.au", "australia.gov.au", "commbank.com.au"
    ]

    # Generate subdomains for legit sites (e.g., mail.google.com, support.apple.com)
    legit_urls = []
    prefixes = ["www", "mail", "support",
                "login", "shop", "blog", "help", "secure"]

    for domain in legit_domains:
        # Add the root domain
        legit_urls.append(f"https://{domain}")
        # Add realistic subdomains
        for p in prefixes:
            legit_urls.append(f"https://{p}.{domain}")
            legit_urls.append(f"https://{domain}/{p}")

    # --- PHISHING SITES ---
    # Constructing thousands of fake variations
    targets = ["paypal", "apple", "google", "netflix",
               "bankofamerica", "chase", "dropbox", "facebook"]
    actions = ["login", "verify", "update", "secure",
               "confirm", "account-alert", "support"]
    separators = ["-", ".", ""]
    tlds = [".xyz", ".tk", ".top", ".club", ".info", ".net", ".org", ".com"]
    # Note: .com is included because phishers use it too (e.g. paypal-secure-update.com)

    phish_urls = []
    for t in targets:
        for a in actions:
            for sep in separators:
                for tld in tlds:
                    # Pattern: target-action.tld (e.g. paypal-verify.tk)
                    url1 = f"http://{t}{sep}{a}{tld}"
                    # Pattern: action-target.tld (e.g. login-apple.xyz)
                    url2 = f"http://{a}{sep}{t}{tld}"
                    phish_urls.append(url1)
                    phish_urls.append(url2)

    # Add some IP-based phishing attacks
    for _ in range(50):
        ip = f"{random.randint(10,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        phish_urls.append(f"http://{ip}/login")
        phish_urls.append(f"http://{ip}/admin")

    return legit_urls, phish_urls


def simulate_html_features(label):
    """
    Simulates what the scraper would see.
    We need this because we can't scrape 2000 sites in real-time for training.
    """
    if label == 1:  # PHISHING
        # Phishing sites usually have:
        # - A password field (Type='password')
        # - Several inputs (User, Pass, PIN)
        # - Often use iframes to hide content
        return [
            random.randint(2, 6),  # inputs
            1,                    # password field (Almost always yes)
            random.choice([0, 1]),  # iframe
            random.randint(0, 20)  # title_length (Often short or empty)
        ]
    else:  # LEGIT
        # Legit sites are mixed.
        # - Login pages have password fields
        # - Homepages might just have search bars
        has_password = random.choices([0, 1], weights=[0.7, 0.3])[
            0]  # 30% chance of login form
        return [
            random.randint(1, 15),  # inputs
            has_password,          # password field
            0,                     # iframe (Rare on legit login pages)
            random.randint(10, 60)  # title_length (Usually descriptive)
        ]


# --- 3. BUILDING DATASET ---
legit_urls, phish_urls = generate_synthetic_data()
print(
    f"📊 Dataset Size: {len(legit_urls)} Legit URLs | {len(phish_urls)} Phishing URLs")

data = []

# Process Legitimate
print("Extracting features for legitimate sites...")
for url in legit_urls:
    try:
        # 1. Get the standard URL features (Math)
        url_feats = extract_url_features(url, fetch_html=False)[:9]
        # 2. Simulate the HTML content (Since we can't scrape them all now)
        html_feats = simulate_html_features(0)
        data.append(url_feats + html_feats + [0])  # Label 0 = Safe
    except Exception as e:
        print(f"Warning: Skipping URL {url} due to error: {str(e)}")
        continue

# Process Phishing
print("Extracting features for phishing sites...")
for url in phish_urls:
    try:
        url_feats = extract_url_features(url, fetch_html=False)[:9]
        html_feats = simulate_html_features(1)
        data.append(url_feats + html_feats + [1])  # Label 1 = Phish
    except Exception as e:
        print(f"Warning: Skipping URL {url} due to error: {str(e)}")
        continue

# Create DataFrame
if not data:
    raise ValueError("No data collected. Cannot create DataFrame.")

columns = [
    "len", "host_len", "spec", "entropy", "digits", "https", "tld", "ip", "www",
    "inputs", "password", "iframe", "title_len",
    "label"
]
df = pd.DataFrame(data, columns=columns)

if len(df) == 0:
    raise ValueError("DataFrame is empty. Cannot train model.")

# --- 4. TRAIN MODEL ---
print("🧠 Training Random Forest Model...")
X = df.drop("label", axis=1)
y = df["label"]

# Split data to test accuracy
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# --- 5. EVALUATE ---
preds = model.predict(X_test)
acc = accuracy_score(y_test, preds)
print(f"✅ Model Accuracy on Test Set: {acc:.2%}")
print("\nClassification Report:")
print(classification_report(y_test, preds))

# --- 6. SAVE ---
try:
    joblib.dump(model, "phishing_model.pkl")
    print("💾 Saved high-fidelity model to 'phishing_model.pkl'")
except Exception as e:
    print(f"❌ Error saving model: {str(e)}")
    raise
