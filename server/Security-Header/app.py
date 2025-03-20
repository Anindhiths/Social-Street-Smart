from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse
# from bs4 import BeautifulSoup
import re
from createBloomFilter import load_bloom_filter

"""
AOSSIE Security Header Checker API for Social Street Smart
==========================================================

This Flask application provides an API to check the security headers of a given URL.
The API analyzes various security headers and assigns a score based on their presence and configuration.
It also checks if the URL is potentially malicious using a Bloom filter.

Features:
- URL validation and normalization
- Malicious URL detection using Bloom filter
- Security header scanning (XSS, Content-Type, X-Frame, HSTS, CSP)
- Scoring based on header presence and configuration

Endpoints:
- GET /: Home endpoint that returns basic API information
- GET/POST /shc: Main endpoint to scan a URL for security headers
"""

app = Flask(__name__)
# Load the Bloom filter for malicious URL detection
bloom_filter = load_bloom_filter("./bloomfilter/bloomFilterObj")

@app.route("/")
def home():
    """
    Home endpoint that returns basic API information.
    
    Returns:
        JSON: Basic information about the API
    """
    return jsonify({"Title": "AOSSIE's Security Header Checker API for Social Street Smart"})

@app.route("/shc", methods=["POST", "GET"])
def scan_url():
    """
    Main endpoint to scan a URL for security headers.
    Accepts both GET and POST requests.
    
    Parameters:
        For GET: URL as a query parameter
        For POST: URL in JSON body
    
    Returns:
        JSON: Score, URL validity status, and the processed URL
    """
    score = 0
    isValid = "False"
    
    # Extract URL from request (either POST JSON or GET query parameter)
    if request.method == "POST":
        if (request.get_json()):
            url = (request.get_json())["url"]
        else:
            return jsonify({"Error": "No URL Found"})
    else:
        if (request.args.get("url")):
            url = request.args.get("url")
        else:
            return jsonify({"Error": "No URL Found"})
    
    try:
        # Process the URL (handle redirects, normalize format)
        url = getLinkFromUrl(url)
        print("\nUrl scheme", urlparse(url),"\n\n")
        
        # Add https if scheme is missing
        if not urlparse(url).scheme:
            url = 'https://' + url
        
        isValid = True
        
        # Check if the URL is potentially malicious
        if(ScanForMaliciousLink(url)==True):
            score = -1
            isValid = False
            print({"Score": score, "isValid": isValid, "url": url})
            return jsonify({"Score": score, "isValid": isValid, "url": url})
        
        # Scan security headers and calculate score
        score = scan_headers(url, score)
    except:
        return jsonify({"Error": "Invalid Url", "url": url})
    
    return jsonify({"Score": score, "isValid": isValid, "url": url})

def getLinkFromUrl(url):
    """
    Process URL to handle redirects and extract actual URL from shortened links.
    
    Parameters:
        url (str): The input URL which might be shortened or contain redirect parameters
    
    Returns:
        str: The processed URL after following redirects or extracting from parameters
    """
    # Handle Facebook redirect links
    if 'l.facebook.com' in url:
        # Use regex to find the URL after 'u='
        match = re.search(r'u=(https?://[^\s&]+)', url)
        if match:
            url = match.group(1)
        return url
    
    # Handle Twitter/t.co shortened links by following the redirect
    if ('twitter.com' in url) or ('t.co/' in url):
        print("twitter url", url, "\n\n")
        try:
            res = requests.get(url, timeout=10, allow_redirects=True)  # Set a timeout of 10 seconds
            res.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
            print("Request successful:", res is not None)
            url = res.url
        except requests.exceptions.RequestException as e:
            print("Request failed:", e)
        
    return url

def ScanForMaliciousLink(url):
    """
    Check if the URL is potentially malicious using the Bloom filter.
    
    Parameters:
        url (str): The URL to check
    
    Returns:
        bool: True if the URL is potentially malicious, False otherwise
    """
    return url in bloom_filter

def scan_headers(url, score):
    """
    Scan security headers of the given URL and calculate a security score.
    
    Parameters:
        url (str): The URL to scan
        score (int): The initial score
    
    Returns:
        int: The final security score after checking all headers
    """
    # Get all headers from the URL response
    headers = (requests.get(url)).headers
    print(headers)
    
    # Check each security header and update the score
    score = scan_xxss(headers, score)
    score = scan_nosniff(headers, score)
    score = scan_xframe(headers, score)
    score = scan_hsts(headers, score)
    score = scan_policy(headers, score)
    
    return score

def scan_xxss(headers, score):
    """
    Check if X-XSS-Protection header is present.
    
    Parameters:
        headers (dict): Response headers
        score (int): Current security score
    
    Returns:
        int: Updated security score
    """
    try:
        if "X-XSS-Protection" in headers:
            score = score + 1
    except:
        print(1)  # Print 1 on exception for debugging
    return score

def scan_nosniff(headers, score):
    """
    Check if X-Content-Type-Options header is set to 'nosniff'.
    
    Parameters:
        headers (dict): Response headers
        score (int): Current security score
    
    Returns:
        int: Updated security score
    """
    try:
        if headers["X-Content-Type-Options"].lower() == "nosniff":
            score = score + 1
    except:
        print(1)  # Print 1 on exception for debugging
    return score

def scan_xframe(headers, score):
    """
    Check if X-Frame-Options header is set to DENY or SAMEORIGIN.
    
    Parameters:
        headers (dict): Response headers
        score (int): Current security score
    
    Returns:
        int: Updated security score
    """
    try:
        if "deny" in headers["X-Frame-Options"].lower():
            score = score + 1
        elif "sameorigin" in headers["X-Frame-Options"].lower():
            score = score + 1
    except:
        print(1)  # Print 1 on exception for debugging
    return score

def scan_hsts(headers, score):
    """
    Check if Strict-Transport-Security header is present.
    
    Parameters:
        headers (dict): Response headers
        score (int): Current security score
    
    Returns:
        int: Updated security score
    """
    try:
        if "Strict-Transport-Security" in headers:
            score = score + 1
    except:
        print(1)  # Print 1 on exception for debugging
    return score

def scan_policy(headers, score):
    """
    Check if Content-Security-Policy header is present.
    
    Parameters:
        headers (dict): Response headers
        score (int): Current security score
    
    Returns:
        int: Updated security score
    """
    try:
        if "Content-Security-Policy" in headers:
            score = score + 1
    except:
        print(1)  # Print 1 on exception for debugging
    return score

if __name__ == "__main__":
    app.run(debug=True)
