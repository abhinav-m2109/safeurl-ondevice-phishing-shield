import os
import sys
import json
import math
import re

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
 
import numpy as np
import pandas as pd
from PIL import Image, ImageDraw, ImageFont
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import skl2onnx
from skl2onnx.common.data_types import FloatTensorType
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verif', 'bank', 'secure', 'account',
    'update', 'confirm', 'paypal', 'apple', 'google', 'microsoft',
    'netflix', 'amazon', 'support', 'service', 'billing', 'security', 'claim'
]

def calculate_entropy(text):
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum([p * math.log2(p) for p in prob])
    return float(entropy)

def extract_features(url_string):
    url_lower = url_string.lower()
    
    # Extract hostname
    hostname = ""
    try:
        if "://" in url_lower:
            hostname = url_lower.split("://")[1].split("/")[0]
        else:
            hostname = url_lower.split("/")[0]
    except Exception:
        hostname = url_lower

    url_length = float(len(url_string))
    dot_count = float(url_string.count('.'))
    hyphen_count = float(url_string.count('-'))
    at_symbol = 1.0 if '@' in url_string else 0.0
    is_https = 1.0 if url_lower.startswith('https://') else 0.0
    
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    clean_host = hostname.split(':')[0]
    is_ip_address = 1.0 if re.match(ip_pattern, clean_host) else 0.0
    
    subdomains = clean_host.split('.')
    if is_ip_address:
        subdomain_count = 0.0
    else:
        subdomain_count = float(max(0, len(subdomains) - 2))
        
    keyword_count = float(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower))
    
    digit_count = float(sum(1 for c in url_string if c.isdigit()))
    
    url_entropy = calculate_entropy(url_string)
    
    return [
        url_length,
        dot_count,
        hyphen_count,
        at_symbol,
        is_https,
        is_ip_address,
        subdomain_count,
        keyword_count,
        digit_count,
        url_entropy
    ]

FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "at_symbol",
    "is_https",
    "is_ip_address",
    "subdomain_count",
    "suspicious_keywords",
    "digit_count",
    "url_entropy"
]
def generate_dataset(n_samples=2400):
    np.random.seed(42)
    
    safe_domains = [
        "google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com",
        "amazon.com", "youtube.com", "stackoverflow.com", "linkedin.com", "reddit.com",
        "bbc.com", "nytimes.com", "chase.com", "wellsfargo.com", "paypal.com"
    ]
    
    safe_paths = [
        "", "/", "/search", "/en/about", "/products/item", "/dashboard", "/profile",
        "/docs/v1/guide", "/news/2026/08/article", "/help/center"
    ]
    
    phish_targets = ["paypal", "chase", "wellsfargo", "appleid", "bankofamerica", "netflix", "microsoft", "google"]
    phish_tlds = [".com", ".net", ".xyz", ".top", ".online", ".site", ".info", ".tk", ".ru"]
    phish_keywords = ["login-secure", "verify-account", "update-billing", "confirm-identity", "security-alert", "banking-portal"]

    data = []

    for _ in range(n_samples // 2):
        domain = np.random.choice(safe_domains)
        path = np.random.choice(safe_paths)
        sub = np.random.choice(["", "www.", "support.", "api.", "m."])
        protocol = "https://" if np.random.rand() > 0.05 else "http://"
        url = f"{protocol}{sub}{domain}{path}"
        feats = extract_features(url)
        data.append(feats + [0]) # 0 = Safe

    for _ in range(n_samples // 2):
        mode = np.random.choice(["typo", "ip", "subdomain_spoof", "keyword_stuffing"])
        protocol = "http://" if np.random.rand() > 0.3 else "https://"
        
        if mode == "ip":
            ip = f"{np.random.randint(10,220)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,254)}"
            kw = np.random.choice(phish_keywords)
            url = f"{protocol}{ip}/{kw}/index.php?id={np.random.randint(1000,99999)}"
        elif mode == "subdomain_spoof":
            target = np.random.choice(phish_targets)
            sub = f"{target}.com-login.user-auth-verify"
            tld = np.random.choice(phish_tlds)
            url = f"{protocol}{sub}.phish-server{tld}/login?user={np.random.randint(1000,9999)}"
        elif mode == "typo":
            target = np.random.choice(phish_targets)
            typo_domain = target.replace('o', '0').replace('l', '1').replace('e', '3') + np.random.choice(phish_tlds)
            url = f"{protocol}{typo_domain}/verify-banking-account"
        else: 
            target = np.random.choice(phish_targets)
            kw1 = np.random.choice(phish_keywords)
            kw2 = np.random.choice(phish_keywords)
            url = f"{protocol}secure-{target}-{kw1}-{kw2}.com/account-login-update-billing.html"
            
        if np.random.rand() > 0.7:
            url += f"@malicious-user:{np.random.randint(100,999)}"
            
        feats = extract_features(url)
        data.append(feats + [1]) 

    df = pd.DataFrame(data, columns=FEATURE_NAMES + ['label'])
    return df

def train_and_export():
    print("🔄 Generating synthetic dataset...")
    df = generate_dataset(2400)
    
    X = df[FEATURE_NAMES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("🌲 Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"📊 Accuracy:  {accuracy_score(y_test, y_pred)*100:.2f}%")
    print(f"🎯 Precision: {precision_score(y_test, y_pred)*100:.2f}%")
    print(f"⚡ Recall:    {recall_score(y_test, y_pred)*100:.2f}%")
    print(f"🏆 F1 Score:  {f1_score(y_test, y_pred)*100:.2f}%")

    print("📦 Exporting model to ONNX format...")
    initial_type = [('float_input', FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = skl2onnx.convert_sklearn(model, initial_types=initial_type, target_opset=12)

    with open("model.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("✅ Successfully exported model.onnx!")

    feature_importances = model.feature_importances_.tolist()
    
    safe_means = X[y == 0].mean().to_dict()
    phish_means = X[y == 1].mean().to_dict()

    xai_config = {
        "feature_names": FEATURE_NAMES,
        "feature_importances": feature_importances,
        "safe_baselines": safe_means,
        "phish_baselines": phish_means,
        "rules": {
            "is_ip_address": {
                "weight": 0.25,
                "label": "Uses Raw IP Address",
                "danger_msg": "Destination uses an IP address instead of a domain name.",
                "safe_msg": "Uses standard domain name registration."
            },
            "is_https": {
                "weight": 0.20,
                "label": "HTTPS Encryption",
                "danger_msg": "Unencrypted connection (HTTP). Bank/login details can be stolen.",
                "safe_msg": "Encrypted HTTPS connection established."
            },
            "suspicious_keywords": {
                "weight": 0.18,
                "label": "Phishing Trigger Keywords",
                "danger_msg": "Contains multiple financial/login urgency keywords.",
                "safe_msg": "No suspicious keywords detected in link structure."
            },
            "subdomain_count": {
                "weight": 0.15,
                "label": "Subdomain Hierarchy",
                "danger_msg": "Excessive subdomain layering to spoof brand names.",
                "safe_msg": "Clean, standard domain hierarchy."
            },
            "url_entropy": {
                "weight": 0.12,
                "label": "Character Randomness (Entropy)",
                "danger_msg": "High character entropy indicating auto-generated phishing string.",
                "safe_msg": "Normal character distribution."
            },
            "at_symbol": {
                "weight": 0.10,
                "label": "@ Symbol Redirect",
                "danger_msg": "Contains '@' character to trick browser into domain redirect.",
                "safe_msg": "Standard URL path syntax."
            }
        }
    }

    with open("xai_config.json", "w") as f:
        json.dump(xai_config, f, indent=2)
    print("✅ Successfully exported xai_config.json!")

def generate_icons():
    print("🎨 Generating extension PNG icons...")
    os.makedirs("icons", exist_ok=True)
    
    sizes = [16, 48, 128]
    for size in sizes:
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        padding = max(1, size // 10)
        draw.ellipse([padding, padding, size - padding, size - padding], fill=(14, 165, 233, 255))
        
        draw.ellipse([padding+2, padding+2, size - padding - 2, size - padding - 2], outline=(255, 255, 255, 220), width=max(1, size // 20))
        
        if size >= 48:
            points = [
                (int(size * 0.3), int(size * 0.5)),
                (int(size * 0.45), int(size * 0.65)),
                (int(size * 0.7), int(size * 0.35))
            ]
            draw.line(points, fill=(255, 255, 255, 255), width=max(2, size // 12))
            
        img.save(f"icons/icon-{size}.png")
    print("✅ Generated icons/icon-16.png, icons/icon-48.png, icons/icon-128.png!")

if __name__ == "__main__":
    train_and_export()
    generate_icons()
