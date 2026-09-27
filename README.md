# Security Code Review Agent — IBM Bob Hackathon

A zero-dependency Python script that scans any public (or private, with a token)
GitHub repository for security vulnerabilities and produces a structured Markdown report.

---

## What it detects

| Category | Examples |
|---|---|
| 🔴 **Hardcoded secrets** | Passwords, API keys, tokens, private keys, AWS credentials |
| 🟠 **SQL injection** | String-concatenated queries, f-string queries, raw `execute()` calls |
| 🟠 **XSS** | `innerHTML`, `document.write()`, `eval()`, React `dangerouslySetInnerHTML` |
| 🟡 **Insecure crypto / auth** | MD5, SHA-1, `verify=False`, `ssl.CERT_NONE`, Django debug/wildcard config |

---

## Requirements

- Python **3.10+** (uses `list[...]` type hints and `str.removesuffix`)
- No third-party packages — uses only the standard library
- A GitHub personal access token is **optional** but strongly recommended
  (unauthenticated requests are limited to 60/hour; authenticated = 5,000/hour)

---

## Setup

```bash
# 1. Clone or copy this folder
cd security-agent

# 2. (Optional but recommended) Create a GitHub token
#    GitHub → Settings → Developer settings → Personal access tokens → Fine-grained
#    Grant: Contents = Read-only  (for private repos)
#    For public repos, no scopes are needed.

# 3. Export the token so you don't have to type it every time
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx   # macOS / Linux
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"  # PowerShell (Windows)
```

---

## Usage

### Basic — public repo, output to terminal
```bash
python security_agent.py --repo https://github.com/owner/repo
```

### Save report to a Markdown file
```bash
python security_agent.py --repo https://github.com/owner/repo --output report.md
```

### Pass your token explicitly
```bash
python security_agent.py \
  --repo https://github.com/owner/repo \
  --token ghp_xxxxxxxxxxxxxxxxxxxx \
  --output report.md
```

### Private repo (token required)
```bash
python security_agent.py \
  --repo https://github.com/myorg/private-repo \
  --output report.md
```
The `GITHUB_TOKEN` env var is read automatically if `--token` is not supplied.

---

## How to test it

### Option A — scan a known-vulnerable demo repo
These repositories are designed for security training and contain intentional vulnerabilities:

```bash
# Python / Django vulnerable app
python security_agent.py \
  --repo https://github.com/anxolerd/dvpwa \
  --output dvpwa_report.md

# Node.js / Express vulnerable app
python security_agent.py \
  --repo https://github.com/appsecco/dvna \
  --output dvna_report.md

# OWASP WebGoat (Java)
python security_agent.py \
  --repo https://github.com/WebGoat/WebGoat \
  --output webgoat_report.md
```

### Option B — create your own test repo with intentional bad code
1. Create a new GitHub repo.
2. Add a file called `test_vulns.py` with content like:

```python
import hashlib, sqlite3

# BAD: hardcoded credentials
DB_PASSWORD = "supersecret123"
API_KEY = "sk-live-abcdef1234567890"

# BAD: SQL injection
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()

# BAD: weak hash
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# BAD: SSL verification disabled
import requests
resp = requests.get("https://api.example.com", verify=False)
```

3. Push it and run the agent against your new repo.

### Option C — dry run on this very repository

```bash
python security_agent.py --repo https://github.com/<your-username>/security-agent
```

---

## Understanding the output

```
[1/4] Parsed owner='anxolerd', repo='dvpwa'
[2/4] Default branch: 'master'
[3/4] Fetching file tree …
      42 total files, 18 match supported extensions
[4/4] Fetching and scanning files …

  [  1/18] dvpwa/settings.py … 3 issue(s) found
  [  2/18] dvpwa/views.py    … 2 issue(s) found
  [  3/18] requirements.txt  … ✓ clean
  ...

📊  Scan complete.
    Files analysed : 18
    Issues found   : 11
```

The generated Markdown report has four sections:

| Section | What it shows |
|---|---|
| **Summary table** | Count per risk level (Critical / High / Medium / Low) |
| **Detailed findings** | For each issue: file, line, why it's dangerous, offending code, fix |
| **Overall recommendations** | Project-wide security improvements |

---

## Project structure

```
security-agent/
├── security_agent.py   ← the main script (single file, no dependencies)
└── README.md           ← this file
```

---

## Extending the agent

The script is designed to be extended. Here are common next steps:

### Add more patterns
In `security_agent.py`, find `SECRET_PATTERNS`, `SQLI_PATTERNS`, `XSS_PATTERNS`, or
`CRYPTO_PATTERNS` and append a `(regex, title)` tuple.

### Add LLM-powered deep review
After `scan_file_statically()` returns, you can call any LLM API with a prompt like:

```python
REVIEW_PROMPT = """
You are a senior application security engineer.
Review the following {language} code for:
- Hardcoded secrets or credentials
- Injection vulnerabilities (SQL, command, LDAP)
- XSS and output encoding issues
- Insecure authentication or session management
- Sensitive data exposure
- Insecure dependencies or imports
- Any other OWASP Top 10 issues

For each issue found, state:
1. Risk level (Critical / High / Medium / Low)
2. Line number
3. Why it is dangerous
4. A fixed version of the code

Code to review:
---
{code}
---
"""
```

Call `client.chat.completions.create(...)` (OpenAI SDK / watsonx compatible endpoint)
and append the structured response to `report.issues`.

### Output formats
Replace or extend `generate_report()` to emit JSON, HTML, or SARIF
(Static Analysis Results Interchange Format, accepted by GitHub Code Scanning).

---

*IBM Bob Hackathon — Security Code Review Agent*
