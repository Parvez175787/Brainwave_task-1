import re
import requests
import validators

# Optional: Set your Google Safe Browsing API key here
GOOGLE_SAFE_BROWSING_API_KEY = None  # Replace with your API key if available

# ✅ Function to check if the URL is valid
def is_valid_url(url):
    return validators.url(url)

# ✅ Function to check if URL contains an IP address
def contains_ip_address(url):
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
    return re.search(ip_pattern, url) is not None

# ✅ Function to check for suspicious keywords
def has_suspicious_keywords(url):
    suspicious_words = ['login', 'verify', 'update', 'bank', 'secure', 'paypal', 'free']
    return any(word in url.lower() for word in suspicious_words)

# ✅ Function to check if the URL is shortened
def is_url_shortened(url):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
    return any(service in url.lower() for service in shorteners)

# ✅ Optional: Check using Google Safe Browsing API
def check_with_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return "Skipped (No API key provided)"
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "phishing-link-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        if response.status_code == 200:
            if response.json().get("matches"):
                return "⚠️ Unsafe - flagged by Google Safe Browsing"
            return "✅ Safe (not flagged)"
        else:
            return "❗ Error with API request"
    except Exception as e:
        return f"❗ Exception: {str(e)}"

# ✅ Main function to scan a URL
def scan_url(url):
    print(f"\n🔎 Scanning URL: {url}")
    
    if not is_valid_url(url):
        return "❌ Invalid URL"

    results = []

    if contains_ip_address(url):
        results.append("⚠️ Contains IP address")

    if has_suspicious_keywords(url):
        results.append("⚠️ Suspicious keywords found")

    if is_url_shortened(url):
        results.append("⚠️ URL shortening detected")

    results.append(f"🔐 Google Safe Browsing: {check_with_google_safe_browsing(url)}")

    if not results:
        return "✅ No phishing signs found"
    return "\n".join(results)

# ✅ Run scanner on sample URLs
if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login",
        "https://bit.ly/xyzabc",
        "https://secure-paypal-login.com/verify",
        "https://www.google.com"
    ]

    for url in test_urls:
        print(scan_url(url))
        print("-" * 50)
