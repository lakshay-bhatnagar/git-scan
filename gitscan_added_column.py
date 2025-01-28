import os
import ssl
import time
import certifi
import requests
import csv
import re
import logging
from datetime import datetime, timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment
import base64
from concurrent.futures import ThreadPoolExecutor

# Set SSL certificates to use certifi's bundle
os.environ['SSL_CERT_FILE'] = certifi.where()

# GitHub token
token = 'ENTER_GITHUB_TOKEN'

# SendGrid API Key (not using right not)
SENDGRID_API_KEY = 'ENTER_SENDGRID_API'

# Sender verified ID (not using right not)
SENDER_EMAIL = 'sender@email.com'

# Sensitive keywords and patterns
sensitive_patterns = [
    r"API[_-]?KEY", r"ACCESS[_-]?TOKEN", r"SECRET", r"PASSWORD", r"PRIVATE[_-]?KEY",
    r"ONEDRIVE", r'"key"\s*:\s*"[^"]+"', r'"password"\s*:\s*"[^"]+"',
    r"https?://[\w.-]*/[\w/-]*", r"sftp://[\w.-]*",
    r"BEGIN\sPRIVATE\sKEY", r"END\sPRIVATE\sKEY", r"BEGIN\sRSA\sPRIVATE\sKEY",
    r"END\sRSA\sPRIVATE\sKEY", r"[0-9a-fA-F]{32,}",  # Hexadecimal secrets
    r"[A-Za-z0-9+/=]{40,}",  # Base64 encoded secrets
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",  # UUIDs
    r"client[_-]?id", r"client[_-]?secret", r"db[_-]?password", r"db[_-]?user",
    r"aws[_-]?access[_-]?key[_-]?id", r"aws[_-]?secret[_-]?access[_-]?key",
    r"azure[_-]?tenant[_-]?id", r"azure[_-]?client[_-]?id", r"azure[_-]?client[_-]?secret",
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IPv4 addresses
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email addresses
    r"mongodb\+srv://[^\"\s]+",  # MongoDB connection strings
    r"postgresql://[^\"\s]+",  # PostgreSQL connection strings
    r"mysql://[^\"\s]+"  # MySQL connection strings
]

# False positive filters
false_positive_terms = [
    "example", "test", "demo", "mock", "sample", "documentation"
]

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to search GitHub code with pagination
def search_github_code(query, token):
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    headers = {"Authorization": f"Bearer {token}"}
    repos = []
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            repos.extend(data.get('items', []))
            url = response.links.get('next', {}).get('url')  # Follow pagination
        else:
            logging.error(f"Failed to fetch code search results: {response.status_code} - {response.text}")
            break
    return repos

def get_last_modified(repo, token):
    commits_url = repo['repository']['commits_url'].replace("{/sha}", f"?path={repo['path']}")
    response = requests.get(commits_url, headers={"Authorization": f"Bearer {token}"} )
    if response.status_code == 200:
        commits = response.json()
        if commits:
            return commits[0]['commit']['committer']['date']
    return "Unknown"

# Function to write results to a CSV file (with full details)
def write_to_csv(results, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Repository URL", "File Link", "Match Type", "Matched Patterns", "Matched Data", "Last Modified", "File Type"])
        for result in results:
            writer.writerow(result)

# Function to check if content matches the domain or sensitive patterns
def has_relevant_matches(file_content, patterns, domain):
    file_content_lower = file_content.lower()
    domain_match = domain in file_content_lower
    sensitive_match = any(re.search(pattern, file_content, re.IGNORECASE) for pattern in patterns)
    return domain_match or sensitive_match

# Function to process each repository
def process_repo(repo, token, all_results, domain):
    file_content_url = repo['url']
    
    while True:  # Retry loop
        response = requests.get(file_content_url, headers={"Authorization": f"token {token}"})
        
        # Check for rate limit errors
        if response.status_code == 403:
            remaining_limit = response.headers.get("X-RateLimit-Remaining", "0")
            reset_time = response.headers.get("X-RateLimit-Reset", "Unknown")
            reset_time = datetime.fromtimestamp(reset_time, tz=timezone.utc)
            logging.warning(f"Rate limit hit. Remaining: {remaining_limit}. Reset at: {reset_time}")
            
            # Check if a Retry-After header is provided
            if 'Retry-After' in response.headers:
                wait_time = int(response.headers['Retry-After'])
                logging.info(f"Retrying after {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            else:
                logging.error("Rate limit hit, but no Retry-After header present. Skipping this file.")
                return
        
        # Successful response
        if response.status_code == 200:
            try:
                file_content = base64.b64decode(response.json().get('content', '')).decode('utf-8')
            except (KeyError, base64.binascii.Error, UnicodeDecodeError) as e:
                logging.error(f"Error decoding content for {repo['html_url']}: {str(e)}")
                return

            if has_relevant_matches(file_content, sensitive_patterns, domain):
                last_modified = get_last_modified(repo, token)
                matched_patterns = [pattern for pattern in sensitive_patterns if re.search(pattern, file_content, re.IGNORECASE)]
                matched_data = []
                
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, file_content, re.IGNORECASE)
                    if matches:
                        matched_data.extend(matches)

                matched_patterns = list(set(matched_patterns))  # Remove duplicates
                file_type = os.path.splitext(repo['name'])[1]

                # Append the full details to the result list if the domain is found
                all_results.append([
                    repo['repository']['html_url'],
                    repo['html_url'],
                    "Sensitive Match",
                    ", ".join(matched_patterns),
                    ", ".join(matched_data),
                    last_modified,
                    file_type
                ])
            return

        # Handle other errors
        else:
            logging.error(f"Failed to fetch file content for {repo['html_url']} - {response.status_code}")
            logging.debug(f"Response headers: {response.headers}")
            return

# Main function
def main():
    all_results = []
    domain = input("Enter company domain (e.g., example.com): ")

    # Generate queries
    queries = [
        f"%40{domain}", f"{domain}", f"{domain} password",
        f"{domain} secret", f"{domain} token", "config",
        ".env", "docker-compose", "aws credentials", "database.yml", "CVE-"
    ]

    # Search repositories
    repos = []
    for query in queries:
        repos.extend(search_github_code(query, token))

    # Process repositories in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        for repo in repos:
            executor.submit(process_repo, repo, token, all_results, domain)

    # Output results
    if all_results:
        if not os.path.exists('Outputs'):
            os.makedirs('Outputs')

        filename = os.path.join('Outputs', f"{domain}_sensitive_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        write_to_csv(all_results, filename)
        logging.info(f"CSV file '{filename}' created successfully.")
    else:
        logging.info("No sensitive data found.")

if __name__ == "__main__":
    main()
