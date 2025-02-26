import os
import ssl
import time
import certifi
import requests
import csv
import re
import logging
from datetime import datetime, timezone
import base64
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# Set SSL certificates
os.environ['SSL_CERT_FILE'] = certifi.where()

token = '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'
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDER_EMAIL = os.getenv('SENDER_EMAIL')

# Sensitive patterns categorized by confidence levels
sensitive_patterns = {
    "High": [
        r"BEGIN\sPRIVATE\sKEY", r"END\sPRIVATE\sKEY",
        r"BEGIN\sRSA\sPRIVATE\sKEY", r"END\sRSA\sPRIVATE\sKEY",
        r"aws[_-]?secret[_-]?access[_-]?key", r"azure[_-]?client[_-]?secret",
        r"(jdbc|odbc|sqlserver|mysql|postgres|database)[-_]?(url|password|user|name)"
    ],
    "Medium": [
        r"API[_-]?KEY", r"ACCESS[_-]?TOKEN", r"client[_-]?secret",
        r"db[_-]?password", r"mongodb\+srv://[^\"\s]+",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ],
    "Low": [
        r"https?://[\w.-]*/[\w/-]*", r"[A-Za-z0-9+/=]{40,}"
    ]
}

false_positive_terms = ["example", "test", "demo", "mock", "sample", "documentation"]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def search_github_code(query, token):
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    headers = {"Authorization": f"Bearer {token}"}
    repos = []
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            repos.extend(response.json().get('items', []))
            url = response.links.get('next', {}).get('url')
        else:
            logging.error(f"Failed to fetch results: {response.status_code}")
            break
    return repos


def get_commit_history(repo, token):
    commits_url = repo['repository']['commits_url'].replace("{/sha}", f"?path={repo['path']}")
    response = requests.get(commits_url, headers={"Authorization": f"Bearer {token}"})
    return response.json() if response.status_code == 200 else []


def get_file_content_at_commit(repo, commit_sha, token):
    file_url = f"https://api.github.com/repos/{repo['repository']['full_name']}/contents/{repo['path']}?ref={commit_sha}"
    response = requests.get(file_url, headers={"Authorization": f"Bearer {token}"})
    if response.status_code == 200:
        try:
            return base64.b64decode(response.json().get('content', '')).decode('utf-8')
        except Exception as e:
            logging.error(f"Error decoding content for {repo['html_url']}: {str(e)}")
    return None


def classify_match(file_content):
    for level, patterns in sensitive_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, file_content, re.IGNORECASE)
            if match:
                return level, pattern, match.group(0)
    return None, None, None


def write_to_csv(results, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Repository URL", "File Link", "Commit Link", "Match Type", "Matched Patterns", "Matched Data", "Last Modified", "File Type", "Confidence Rating"])
        for result in results:
            writer.writerow(result)


def process_repo(repo, token, all_results, domain):
    commits = get_commit_history(repo, token)
    for commit in commits:
        commit_sha = commit['sha']
        commit_url = f"https://github.com/{repo['repository']['full_name']}/commit/{commit_sha}"
        file_content = get_file_content_at_commit(repo, commit_sha, token)
        if file_content:
            confidence, matched_pattern, matched_data = classify_match(file_content)
            if confidence:
                last_modified = commit['commit']['committer']['date']
                file_type = os.path.splitext(repo['name'])[1]
                all_results.append([
                    repo['repository']['html_url'], repo['html_url'], commit_url,
                    "Sensitive Match", matched_pattern, matched_data, last_modified, file_type, confidence
                ])


def main():
    print(Fore.CYAN + "GitScan - GitHub Sensitive Data Scanner" + Style.RESET_ALL)
    domain = input("Enter company domain (e.g., example.com): ")

    queries = [f"%40{domain}", f"{domain} password", f"{domain} secret", ".env", "aws credentials"]

    repos = []
    for query in queries:
        repos.extend(search_github_code(query, token))

    all_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for repo in repos:
            executor.submit(process_repo, repo, token, all_results, domain)

    if all_results:
        if not os.path.exists('Outputs'):
            os.makedirs('Outputs')
        filename = os.path.join('Outputs', f"{domain}_sensitive_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        write_to_csv(all_results, filename)
        logging.info(Fore.GREEN + f"CSV file '{filename}' created successfully." + Style.RESET_ALL)
    else:
        logging.info("No sensitive data found.")


if __name__ == "__main__":
    main()
