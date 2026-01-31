import math
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def calculate_entropy(text):
    """Calculates Shannon Entropy. Higher = more random/suspicious."""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_url_content(url):
    """Fetches URL content safely with a timeout."""
    try:
        # 3-second timeout prevents the scanner from hanging on dead sites
        response = requests.get(url, timeout=3, allow_redirects=True)
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException:
        # Handle all request-related exceptions (timeout, connection error, etc.)
        return None
    except Exception:
        # Handle any other unexpected errors
        return None
    return None


def extract_html_features(html_content):
    """Extracts security features from the HTML body."""
    if not html_content:
        # Return 0s if content couldn't be scraped
        return [0, 0, 0, 0]

    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. Count Input Fields (Phishing sites usually want data)
    inputs = soup.find_all('input')
    num_inputs = len(inputs)

    # 2. Check for Password Field (Critical for credential harvesting)
    has_password = 1 if any(i.get('type') == 'password' for i in inputs) else 0

    # 3. Check for Iframes (Used to hide malicious content)
    has_iframe = 1 if soup.find_all('iframe') else 0

    # 4. Title Length (Phishing sites often have empty or generic titles)
    title_len = len(
        soup.title.string) if soup.title and soup.title.string else 0

    return [num_inputs, has_password, has_iframe, title_len]


def extract_url_features(url, fetch_html=False):
    """
    Extracts 13 features total (9 URL + 4 Content).
    fetch_html: Set to True for live scanning, False for synthetic training.
    """
    # Validate URL
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""

    # --- Lexical Features (Fast) ---
    lexical_features = [
        len(url),
        len(hostname),
        sum(1 for c in url if c in ['@', '?', '-', '=', '.', '#', '%']),
        calculate_entropy(url),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0,
        1 if any(tld in url for tld in ['.xyz', '.top', '.tk']) else 0,
        1 if re.search(r'\d{1,3}\.\d{1,3}\.', url) else 0,
        1 if 'www' in url else 0
    ]

    # --- Content Features (Slow) ---
    if fetch_html:
        html = get_url_content(url)
        content_features = extract_html_features(html)
    else:
        # Default zeros for training on fake data
        content_features = [0, 0, 0, 0]

    return lexical_features + content_features
