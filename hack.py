# url_checker.py

import requests
from urllib.parse import urlparse

def is_phishing(url):
    try:
        # Check if the URL is reachable
        response = requests.get(url, timeout=10)
        
        # Check if the domain is suspicious (you can replace this logic with more advanced techniques)
        parsed_url = urlparse(url)
        suspicious_domains = ["example.com", "suspicious-site.com"]  # Replace with a real list
        if parsed_url.netloc in suspicious_domains:
            return True
        
        # Check if the response status code indicates potential phishing (e.g., redirects, 404 errors)
        if response.status_code in [301, 302]:  # Redirects might be suspicious
            return True
        elif response.status_code == 404:
            return False  # Not phishing, just a broken link
        
        return False  # If no suspicious indicators are found
    except requests.exceptions.RequestException:
        return True  # If there is any issue in connecting, assume phishing

def main():
    url = input("Enter URL to check: ")
    if is_phishing(url):
        print(f"The URL {url} is suspicious or potentially a phishing link.")
    else:
        print(f"The URL {url} seems safe.")

if __name__ == "__main__":
    main()
