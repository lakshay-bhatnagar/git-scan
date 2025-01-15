import os
import ssl
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

# Set SSL certificates to use certifi's bundle
os.environ['SSL_CERT_FILE'] = certifi.where()

# GitHub token
token = 'ENTER_GITHUB_TOKEN'

# Sendgrid API Key
SENDGRID_API_KEY = 'ENTER_SENDGRID_API'

# Sender verified ID
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
    r"azure[_-]?tenant[_-]?id", r"azure[_-]?client[_-]?id", r"azure[_-]?client[_-]?secret"
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
            logging.error(f"Failed to fetch code search results: {response.status_code}")
            break
    return repos

# Function to write repository links to a CSV file
def write_to_csv(results, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Repository URL", "File Link", "Match Type", "Matched Patterns"])
        for result in results:
            writer.writerow(result)

# Function to send email with attachment using SendGrid
def send_email_with_sendgrid(api_key, sender_email, recipient_email, subject, body, attachment_path):
    message = Mail(
        from_email=sender_email,
        to_emails=recipient_email,
        subject=subject,
        html_content=body
    )

    # Attach the file if it exists
    if os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as file:
            file_data = file.read()
            encoded_file = base64.b64encode(file_data).decode()
            attachment = Attachment(
                file_content=encoded_file,
                file_type='text/csv',
                file_name=os.path.basename(attachment_path),
                disposition='attachment'
            )
            message.attachment = attachment
    else:
        logging.error(f"File not found: {attachment_path}")
        return

    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        logging.info(f"Email sent successfully! Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Function to process each repository
def process_repo(repo, token, all_results):
    file_content_url = repo['url']
    response = requests.get(file_content_url, headers={"Authorization": f"token {token}"})
    if response.status_code == 200:
        try:
            file_content = base64.b64decode(response.json().get('content', '')).decode('utf-8')
        except (KeyError, base64.binascii.Error, UnicodeDecodeError):
            logging.error(f"Error decoding content for {repo['html_url']}")
            return

        # Normalize content and check for false positives
        file_content = file_content.strip().lower()
        if any(term in file_content for term in false_positive_terms):
            return

        matches = []
        for pattern in sensitive_patterns:
            try:
                match = re.findall(pattern, file_content, re.IGNORECASE)
                if match:
                    matches.extend(match)
            except re.error as e:
                logging.error(f"Invalid regex pattern: {pattern} ({e})")

        if matches:
            all_results.append([
                repo['repository']['html_url'],
                repo['html_url'],
                "Sensitive Match",
                ", ".join(set(matches))  # Avoid duplicates
            ])

# Main function
def main():
    all_results = []
    company_name = input("Enter company domain (e.g., example.com): ")

    # Search for company domain
    queries = [
        f"%40{company_name}",  # Search for company domain
        f"{company_name}",  # Search for company name
        f"{company_name} password",  # Search for company name with password
        f"{company_name} secret",  # Search for company name with secret
        f"{company_name} token"  # Search for company name with token
    ]

    repos = []
    for query in queries:
        repos.extend(search_github_code(query, token))

    # Process each repository in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        for repo in repos:
            executor.submit(process_repo, repo, token, all_results)

    if all_results:
        # Create 'Outputs' directory if it doesn't exist
        if not os.path.exists('Outputs'):
            os.makedirs('Outputs')

        # Generate filename with current date and time
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join('Outputs', f"{company_name}_sensitive_data_{current_time}.csv")
        write_to_csv(all_results, filename)
        logging.info(f"CSV file '{filename}' created successfully.")

        # Email Configuration
        sendgrid_api_key = SENDGRID_API_KEY
        sender_email = SENDER_EMAIL
        recipient_email = input("Enter recipient email: ")
        subject = "Sensitive Data Findings Report"
        body = "Please find attached the CSV file containing the sensitive data findings."
        send_email_with_sendgrid(sendgrid_api_key, sender_email, recipient_email, subject, body, filename)
    else:
        logging.info("No sensitive data found.")

if __name__ == "__main__":
    main()