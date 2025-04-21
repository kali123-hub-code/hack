import tkinter as tk
from tkinter import messagebox
import validators
from urllib.parse import urlparse


# Simple phishing detection function (you can expand this)
def is_phishing(url):
    # Basic URL validation
    if not validators.url(url):
        return "Invalid URL"
    
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Check for suspicious patterns
    if parsed_url.scheme != "https":  # HTTPS is generally safer
        return "Warning: HTTP instead of HTTPS"
    
    # Example suspicious domain check (you can add more patterns here)
    suspicious_keywords = ['paypal', 'bank', 'account', 'login']
    if any(keyword in parsed_url.netloc.lower() for keyword in suspicious_keywords):
        return "Suspicious domain detected!"
    
    return "URL seems safe"


# Function to handle the button click and URL check
def check_url():
    url = url_entry.get()
    result = is_phishing(url)
    if result == "Invalid URL":
        messagebox.showerror("Error", "Please enter a valid URL.")
    elif result == "Warning: HTTP instead of HTTPS":
        messagebox.showwarning("Warning", result)
    elif result == "Suspicious domain detected!":
        messagebox.showwarning("Warning", result)
    else:
        messagebox.showinfo("Safe", result)


# Set up the main window using Tkinter
root = tk.Tk()
root.title("URL Phishing Checker")

# Set the window size
root.geometry("400x200")

# URL label
url_label = tk.Label(root, text="Enter URL to check:")
url_label.pack(pady=10)

# URL input field
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=10)

# Check button
check_button = tk.Button(root, text="Check URL", command=check_url)
check_button.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()
import re
import requests
import sys
if len(sys.argv) > 1:
    user_url = sys.argv[1]
else:
    user_url = input("Enter a URL to check: ").strip()
# Keywords often found in phishing or suspicious URLs
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'bank', 'secure', 'paypal', 'account', 'signin']
user_url = input("Enter a URL to check: ").strip()
def is_valid_url(url):
    """
    Validates the format of a URL using a regex pattern.
    """
    pattern = re.compile(
        r'^(https?://)?'              # optional http or https
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'  # domain name
        r'(:\d+)?'                    # optional port
        r'(\/\S*)?$'                  # optional path
    )
    return re.match(pattern, url)

def is_url_live(url):
    """
    Checks if the URL is reachable (status code 200).
    """
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_suspicious(url):
    """
    Checks for the presence of suspicious keywords in the URL.
    """
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def check_url(url):
    """
    Full URL check: format, availability, and keyword flag.
    """
    if not is_valid_url(url):
        return {
            "url": url,
            "error": "Invalid URL format."
        }

    if not url.startswith("http"):
        url = "http://" + url

    live_status = is_url_live(url)
    suspicious = check_suspicious(url)

    return {
        "url": url,
        "is_live": live_status,
        "suspicious_keywords_found": suspicious
    }

if __name__ == "__main__":
    user_url = input("Enter a URL to check: ").strip()
    result = check_url(user_url)
    print("\n--- URL Check Result ---")
    for key, value in result.items():
        print(f"{key}: {value}")
import requests
import tldextract

# Optionally use Google's Safe Browsing API
# You need to replace YOUR_API_KEY with a real key from: https://developers.google.com/safe-browsing/
GOOGLE_API_KEY = 'YOUR_API_KEY'
GOOGLE_API_URL = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}'

def check_google_safe_browsing(url):
    payload = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(GOOGLE_API_URL, json=payload)
        if response.status_code == 200:
            if response.json().get("matches"):
                return True
            else:
                return False
        else:
            print("Error contacting Google Safe Browsing API.")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def simple_heuristics(url):
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    if len(url) > 75:
        print("⚠️ Long URL detected")
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        print("⚠️ Suspicious keyword in URL")
    if '@' in url or '-' in tldextract.extract(url).domain:
        print("⚠️ Unusual characters in domain")
    
def phishing_check(url):
    print(f"\n🔎 Checking URL: {url}")
    
    print("\n[1] Running basic heuristics...")
    simple_heuristics(url)
    
    print("\n[2] Checking Google Safe Browsing...")
    result = check_google_safe_browsing(url)
    if result:
        print("❌ URL is flagged as dangerous by Google Safe Browsing.")
    elif result is False:
        print("✅ URL is not flagged by Google Safe Browsing.")
    else:
        print("⚠️ Could not determine status from Google API.")

# Example usage
user_url = input("Enter URL to check: ")
phishing_check(user_url)
