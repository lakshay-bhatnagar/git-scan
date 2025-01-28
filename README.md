# GitHub Sensitive Data Scanner

This project is a Python-based tool designed to search for sensitive information within GitHub repositories. It scans repositories for patterns such as API keys, passwords, secrets, and other sensitive data based on customizable regular expressions.

## Features
- Search GitHub repositories using specified queries.
- Match sensitive patterns (e.g., API keys, secrets, private keys) in repository files.
- Outputs results to a CSV file with matched patterns and corresponding data.
- Handles GitHub API rate limiting.
- Multi-threaded processing for faster results.
- Logging for detailed debugging and status updates.

## Prerequisites
1. **Python Version**: Ensure Python 3.7 or higher is installed.
2. **GitHub Personal Access Token (PAT)**:
   - A GitHub PAT is required to authenticate API requests.
   - Token scopes: `repo` and `read:org` (adjust based on your needs).
   - [Generate a token here](https://github.com/settings/tokens).
3. **Python Libraries**:
   Install the following libraries:
   ```bash
   pip install certifi requests colorama
   ```

## Installation
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/lakshay-bhatnagar/git-scan.git
   cd git-scan
   ```
2. Create a Python virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration
1. Open the script and replace the placeholders:
   - `GITHUB_TOKEN`: Your GitHub Personal Access Token.
   - `SENDGRID_API_KEY` (optional, if email notifications are required).

2. Customize the list of sensitive patterns in the `sensitive_patterns` variable as needed.

## Usage
Run the script by executing:
```bash
python main.py
```
### Script Flow
1. **Input**: The script prompts for a company domain to tailor the search queries.
2. **Search**: Queries GitHub's code search API for repositories containing sensitive information.
3. **Process**: Scans each repository file for sensitive patterns and logs results.
4. **Output**: Results are saved to a CSV file in the `Outputs` directory.

### Output Example
The CSV file includes:
- Repository URL
- File Link
- Match Type
- Matched Patterns
- Matched Data
- Last Modified
- File Type

## Screenshots

### Example Screenshot Placeholder
![Screenshot](screenshots/example.png)

## Handling Rate Limits
- The script includes logic to handle GitHub's API rate limiting.
- If rate limits are hit, it pauses until the reset time provided by GitHub.
- Logs provide detailed information about rate limits and reset times.

## Debugging and Logs
- Logs are saved to the console and include detailed error and status messages.
- Adjust logging levels as needed in the script (default: `INFO`).

## Known Limitations
- GitHub's API rate limits may slow down large-scale scans.
- Some false positives may occur depending on the patterns defined.

## Contribution
Feel free to contribute by submitting pull requests or reporting issues.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
