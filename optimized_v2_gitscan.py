import os
import ssl
import time
import certifi
import requests
import csv
import re
import logging
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment
import base64
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# Set SSL certificates to use certifi's bundle
os.environ['SSL_CERT_FILE'] = certifi.where()

# GitHub token
token = 'GITSCAN_KEY'

# Sensitive keywords and patterns
sensitive_patterns = [
    r"\b(API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)\b",
    r"\b(ONEDRIVE|SFTP|DATABASE[_-]?URL|DB[_-]?PASSWORD|DB[_-]?USER)\b",
    r'"(password|key|token)"\s*:\s*"[^"]+"',
    r'https?://[\w.-]+/[\w/-]*',
    r'BEGIN\s(EC|RSA)?PRIVATE\sKEY',
    r'[0-9a-fA-F]{32,}',  # Hexadecimal secrets
    r'[A-Za-z0-9+/=]{40,}',  # Base64 encoded secrets
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    r'\b(client[_-]?id|client[_-]?secret|aws[_-]?access[_-]?key[_-]?id)\b',
    r'\b(aws[_-]?secret[_-]?access[_-]?key|azure[_-]?tenant[_-]?id)\b',
    r'\b(azure[_-]?client[_-]?id|db[_-]?url|db[_-]?host)\b',
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IPv4 addresses
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
    r'mongodb\+srv://[^"\s]+',
    r'(postgresql|mysql)://[^"\s]+',
    r'\b(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp)\b',  # SSH keys
    r'"?(auth|token|password|secret|key)"?\s*[:=]\s*"?[a-zA-Z0-9_\-]{8,}"?',
    r'"?(account|user|email|login)"?\s*[:=]\s*"?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"?'
]

# False positive filters
false_positive_terms = [
    "example", "test", "demo", "mock", "sample", "documentation", "localhost", "public"
]

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to write results to CSV
def write_to_csv(data, filename):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Repository URL", "File URL", "Commit URL", "Type", "Matched Patterns", "Matched Data", "Confidence Score"])
        writer.writerows(data)

# Function to search GitHub code with pagination and error handling
def search_github_code(query, token):
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    headers = {"Authorization": f"Bearer {token}"}
    repos = []
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            repos.extend(data.get('items', []))
            url = response.links.get('next', {}).get('url')
        elif response.status_code == 403 and 'rate limit' in response.text.lower():
            logging.warning("Rate limit reached, sleeping for 60 seconds...")
            time.sleep(60)
            continue
        else:
            logging.error(f"Failed to fetch code search results: {response.status_code} - {response.text}")
            break
    return repos

# Main function
def main():
    all_results = []
    domain = input("Enter company domain (e.g., example.com): ").lower()
    queries = [f'"{domain}"', f'"{domain}" password', f'"{domain}" secret', "config", ".env"]
    repos = []
    for query in queries:
        repos.extend(search_github_code(query, token))
    if all_results:
        filename = f"Outputs/{domain}_sensitive_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        os.makedirs('Outputs', exist_ok=True)
        write_to_csv(all_results, filename)
        logging.info(f"CSV file '{filename}' created successfully.")
    else:
        logging.info("No sensitive data found.")

if __name__ == '__main__':
    main()
