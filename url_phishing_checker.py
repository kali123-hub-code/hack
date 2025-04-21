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
