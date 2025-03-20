#!/usr/bin/env python3
"""
SSL Validator API for Social Street Smart

This Flask application provides an API for validating SSL certificates of websites.
It checks if SSL certificates are valid and safe based on expiration dates and validity periods.
The API can handle URLs from various social media platforms and follows redirects to validate the final destination.

Dependencies:
    - OpenSSL
    - cryptography
    - idna
    - Flask
    - requests
    - BeautifulSoup
    - re
"""

from OpenSSL import SSL
from cryptography import x509
import idna
from datetime import datetime
from socket import socket
from flask import Flask, jsonify, request
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re

# Initialize Flask application
app = Flask(__name__)

@app.route("/")
def home():
    """
    Root endpoint that returns basic API information.
    
    Returns:
        JSON: Basic information about the API
    """
    return jsonify({"Title": "AOSSIE's SSL Validator API for Social Street Smart"})

@app.route("/ssl", methods=["POST", "GET"])
def check_url():
    """
    Main endpoint for checking SSL validity and safety of a URL.
    Accepts both GET and POST requests with a URL parameter.
    
    Returns:
        JSON: Contains SSL validation results including:
            - isSafe: Whether the certificate is considered safe
            - isValid: Whether the certificate is currently valid
            - url: The URL that was checked (after following redirects)
    """
    isSafe = "False"
    isValid = "False"
    
    # Extract URL from request (either POST JSON or GET query parameter)
    if request.method == "POST":
        if (request.get_json()):
            url = (request.get_json())["url"]
        else:
            return jsonify({"Error": "No Url Found"})
    else:
        if (request.args.get("url")):
            url = request.args.get("url")
        else:
            return jsonify({"Error": "No Url Found"})
    
    print(url)
    try:
        # Process URL and check SSL safety
        url = getLinkFromUrl(url)
        hostname = get_hostname(url)
        if (hostname):
            isValid, isSafe = check_safety(hostname, isSafe, isValid)
    except:
        return jsonify({"Error": "Invalid Url"})
    
    return jsonify(
        {"isSafe": isSafe,
         "isValid": isValid,
         "url": url})

def getLinkFromUrl(url):
    """
    Processes URLs from various social media platforms and follows redirects to get the final destination URL.
    
    Handles special cases for:
    - Facebook l.facebook.com links
    - Reddit links
    - Twitter t.co shortened links
    
    Args:
        url (str): The original URL to process
        
    Returns:
        str: The final destination URL after following redirects
    """
    if 'l.facebook.com' in url:
        # Use regex to find the URL after 'u='
        match = re.search(r'u=(https?://[^\s&]+)', url)
        if match:
            url = match.group(1)
        return url
    elif 'reddit.com' in url:
        pageReq = requests.head(url, allow_redirects=True)
        soup = BeautifulSoup(pageReq.content, 'lxml')
        url = soup.find("meta", property="og:url")
    
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

def get_hostname(url):
    """
    Extracts the hostname from a URL, adding the https scheme if not present.
    
    Args:
        url (str): URL to extract hostname from
        
    Returns:
        str: Hostname extracted from the URL
    """
    if not urlparse(url).scheme:
        url = 'https://' + url
    hostname = urlparse(url).netloc
    return hostname

def check_safety(hostname, isSafe="False", isValid="False"):
    """
    Checks the SSL certificate of a given hostname for validity and safety.
    
    A certificate is considered:
    - Valid if it's currently within its validity period
    - Safe if it's valid AND has more than 30 days between not_before and not_after dates
    
    Args:
        hostname (str): The hostname to check
        isSafe (str): Initial safety status, defaults to "False"
        isValid (str): Initial validity status, defaults to "False"
        
    Returns:
        tuple: (isValid, isSafe) - Both strings containing "True" or "False"
    """
    try:
        # Convert hostname to IDNA format for SSL verification
        hostname_idna = idna.encode(hostname)
    except:
        isValid = "False"
        isSafe = "False"
        return (isValid, isSafe)
    
    # Establish a socket connection to the host
    sock = socket()
    try:
        sock.connect((hostname, 443))
    except:
        isValid = "False"
        isSafe = "False"
        return (isValid, isSafe)
    
    # Set up SSL context
    ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    
    # Establish SSL connection
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    
    # Get certificate information
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()
    
    # Extract validity dates
    not_before = crypto_cert.not_valid_before
    not_after = crypto_cert.not_valid_after
    
    # Determine validity and safety
    if ((datetime.now() < not_after and (not_after - not_before).days > 30)):
        isValid = "True"
        isSafe = "True"
    else:
        isValid = "True"
        isSafe = "False"
    
    return (isValid, isSafe)

if __name__ == "__main__":
    app.run(debug=True)
