import os
import re
import requests
import pandas as pd
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
load_dotenv()

# ========== Config ==========
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
if not API_KEY:
    logging.warning("Google Safe Browsing API key not found. This check will be disabled.")

# A failsafe whitelist for major domains that should never be flagged.
WHITELISTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'twitter.com', 'linkedin.com',
    'instagram.com', 'reddit.com', 'github.com'
}

# ========== Helpers ==========
def get_domain(url: str) -> str:
    """Extracts the base domain (e.g., 'google.com') from a URL."""
    try:
        if not re.match(r'http[s]?://', url):
            url = 'http://' + url
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc.lower()
        # Remove 'www.' from the beginning if it exists
        if netloc.startswith('www.'):
            return netloc[4:]
        return netloc
    except Exception:
        return url.lower()

# ========== Data Loading ==========
def load_kaggle_domains():
    """Loads the phishing dataset and pre-processes it for high-performance lookups."""
    try:
        drive_url = "https://drive.google.com/uc?id=13lsygqMVSnrstBRGHjEC1IycsALYD8WJ&export=download"
        df = pd.read_csv(drive_url)
        df.columns = df.columns.str.lower()
        bad_urls = df[df['label'].str.lower() == 'bad']['url']
        # Apply the same get_domain logic to the dataset for accurate matching
        phishing_domains = {get_domain(url) for url in bad_urls.dropna()}
        logging.info(f"Loaded {len(phishing_domains)} unique phishing DOMAINS from dataset.")
        return phishing_domains
    except Exception as e:
        logging.error(f"Failed to load dataset from Google Drive: {e}")
        return set()

KAGGLE_PHISHING_DOMAINS = load_kaggle_domains()

# ========== Phishing Check Functions ==========
def is_in_kaggle_dataset(domain: str) -> bool:
    """Checks if the URL's exact domain is in the pre-loaded set."""
    return domain in KAGGLE_PHISHING_DOMAINS

def check_safe_browsing_api(url: str) -> bool:
    """Checks the URL against Google's Safe Browsing API."""
    if not API_KEY:
        return False
    payload = {
        "client": {"clientId": "netdefend", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}", json=payload, timeout=5)
        response.raise_for_status()
        return bool(response.json().get("matches"))
    except requests.exceptions.RequestException as e:
        logging.warning(f"Safe Browsing API request error: {e}")
        return False

def is_suspicious_url(url: str, domain: str) -> bool:
    """FINAL HEURISTICS (Corrected): Detects suspicious URLs with reliable checks."""
    # Check for lookalike characters (homoglyphs)
    if any(char in domain for char in ['0', '1', '5']): # Simple but effective check for o, l, s
        return True
    # Check for repeated characters (e.g., faceboook)
    if re.search(r'(.)\1\1', domain):
        return True
    # Check for IP Address in domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return True
    # Check for '@' symbol in URL
    if '@' in url:
        return True
    # Check for excessive subdomains or hyphens (more conservative)
    if domain.count('.') > 4 or domain.count('-') > 3:
        return True
    return False

# ========== FastAPI Application ==========
app = FastAPI(title="NetDefend Phishing Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["POST"], allow_headers=["*"])

class URLItem(BaseModel):
    url: str

@app.post("/check")
async def check_url_endpoint(item: URLItem):
    url = item.url.strip()
    if not url:
        return {"error": "No URL provided", "is_phishing": False}

    domain = get_domain(url)
    
    # 1. Check against the failsafe whitelist first.
    if domain in WHITELISTED_DOMAINS:
        return {"url": url, "is_phishing": False, "reasons": ["Domain is on the global whitelist"]}

    reasons = []
    
    if is_suspicious_url(url, domain):
        reasons.append("URL structure matches suspicious patterns")
    if is_in_kaggle_dataset(domain):
        reasons.append("Domain found in threat dataset")
    if check_safe_browsing_api(url):
        reasons.append("Flagged by Google Safe Browsing")

    is_phishing = bool(reasons)
    return {"url": url, "is_phishing": is_phishing, "reasons": reasons if is_phishing else ["No threats detected"]}