import os
import re
import requests
import pandas as pd
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Load environment variables from a .env file for local development
load_dotenv()

# ========== Config ==========
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
if not API_KEY:
    logging.warning("Google Safe Browsing API key not found. This check will be disabled.")

# ========== Helpers ==========
def get_domain(url: str) -> str:
    """Extracts the network location (domain) from a URL."""
    try:
        # Assume http if no scheme is present
        if not re.match(r'http[s]?://', url):
            url = 'http://' + url
        return urlparse(url).netloc.lower()
    except Exception:
        # Fallback for malformed URLs
        return url.lower()

# ========== Data Loading (Optimized) ==========
def load_kaggle_domains():
    """
    Loads the phishing dataset and pre-processes it into a set of unique domains
    for high-performance lookups. This runs only once at startup.
    """
    try:
        # Direct download link for the Google Drive file
        drive_url = "https://drive.google.com/uc?id=13lsygqMVSnrstBRGHjEC1IycsALYD8WJ&export=download"
        df = pd.read_csv(drive_url)
        df.columns = df.columns.str.lower()
        
        bad_urls = df[df['label'].str.lower() == 'bad']['url']
        
        # REFACTORED: Convert all URLs to domains and store in a set for O(1) lookups
        phishing_domains = {get_domain(url) for url in bad_urls.dropna()}
        
        logging.info(f"Loaded {len(phishing_domains)} unique phishing DOMAINS from dataset.")
        return phishing_domains
    except Exception as e:
        logging.error(f"Failed to load dataset from Google Drive: {e}")
        return set()

# Load the data once when the application starts
KAGGLE_PHISHING_DOMAINS = load_kaggle_domains()

# ========== Phishing Check Functions ==========
def is_in_kaggle_dataset(url: str) -> bool:
    """
    REFACTORED: Checks if the URL's domain is in the pre-loaded set.
    This is now a highly efficient O(1) operation.
    """
    domain = get_domain(url)
    return domain in KAGGLE_PHISHING_DOMAINS

def check_safe_browsing_api(url: str) -> bool:
    """Checks the URL against Google's Safe Browsing API."""
    if not API_KEY:
        return False
        
    payload = {
        "client": {"clientId": "netdefend-extension", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
            json=payload
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()
        return bool(data.get("matches"))
    except requests.exceptions.RequestException as e:
        logging.warning(f"Safe Browsing API request error: {e}")
        return False

def is_suspicious_url(url: str) -> bool:
    """
    IMPROVED HEURISTICS: Uses more reliable patterns to detect suspicious URLs
    and reduce false positives from the previous version.
    """
    domain = get_domain(url)
    
    # 1. IP Address in domain: URLs using a raw IP are highly suspicious.
    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_regex, domain):
        return True
        
    # 2. '@' symbol in URL: Often used to obscure the actual domain.
    if '@' in url:
        return True
        
    # 3. Excessive subdomains: Phishers often use many subdomains. e.g., login.secure.mybank.com.scam.net
    if domain.count('.') > 3:
        return True
        
    # 4. Excessive hyphens in domain: Another common phishing pattern.
    if domain.count('-') > 2:
        return True
        
    return False

# ========== FastAPI Application ==========
app = FastAPI(
    title="NetDefend Phishing Detector API",
    description="An API to detect potentially malicious or phishing URLs."
)

# --- IMPORTANT ---
# For production, you MUST restrict the origins to your Chrome extension's ID.
# Example: allow_origins=["chrome-extension://<your-extension-id-here>"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # WARNING: Permissive for testing only.
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)

class URLItem(BaseModel):
    url: str

@app.post("/check")
async def check_url_endpoint(item: URLItem):
    """
    Endpoint to check a URL. It aggregates results from multiple detection methods.
    """
    url = item.url.strip()
    if not url:
        return {"error": "No URL provided", "is_phishing": False}

    reasons = []
    
    # Perform checks
    if check_safe_browsing_api(url):
        reasons.append("Flagged by Google Safe Browsing")
        
    if is_in_kaggle_dataset(url):
        reasons.append("Domain found in threat dataset")
        
    if is_suspicious_url(url):
        reasons.append("URL structure matches suspicious patterns")

    is_phishing = bool(reasons)
    
    return {
        "url": url,
        "is_phishing": is_phishing,
        "reasons": reasons if is_phishing else ["No threats detected"]
    }