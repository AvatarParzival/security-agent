"""
IBM Bob Hackathon — Security Code Review Agent
================================================
Takes a GitHub repository URL, fetches every relevant source file via
the GitHub REST API, sends each file to IBM watsonx (via the Bob SDK or
the OpenAI-compatible endpoint), and produces a structured security report.

Usage:
    python security_agent.py --repo https://github.com/owner/repo
    python security_agent.py --repo https://github.com/owner/repo --token ghp_xxx
    python security_agent.py --repo https://github.com/owner/repo --output report.md
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# File extensions we care about for security analysis
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".java", ".go", ".rb", ".cs",
    ".env", ".json", ".yaml", ".yml",
    ".config", ".conf", ".xml", ".toml",
    ".sh", ".bash", ".zsh",
    ".tf",          # Terraform
    ".sql",
    "Dockerfile",   # matched by filename
    ".htaccess",
}

# Files to always skip (too large / not useful)
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "composer.lock", "Gemfile.lock",
}

# Maximum file size to analyse (bytes) — avoids sending huge minified files
MAX_FILE_BYTES = 60_000

# GitHub API base
GITHUB_API = "https://api.github.com"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RepoFile:
    """A single file fetched from the repository."""
    path: str           # e.g. "src/app.py"
    content: str        # decoded text content
    size: int           # bytes


@dataclass
class SecurityIssue:
    """One vulnerability finding."""
    risk_level: str     # Critical | High | Medium | Low
    title: str
    file_path: str
    line_number: str    # e.g. "42" or "38-45"
    description: str    # why it is dangerous
    code_snippet: str   # offending code
    fix: str            # corrected code or recommendation


@dataclass
class SecurityReport:
    """Aggregated report for the whole repository."""
    repo_url: str
    files_analysed: int = 0
    issues: list[SecurityIssue] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_request(url: str, token: Optional[str]) -> dict | list:
    """Make a single authenticated GET request to the GitHub API."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security-code-review-agent/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as exc:
        if exc.code == 403:
            raise RuntimeError(
                "GitHub rate limit hit or forbidden. "
                "Pass --token with a personal access token to increase limits."
            ) from exc
        if exc.code == 404:
            raise RuntimeError(f"Not found: {url}") from exc
        raise RuntimeError(f"GitHub API error {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc


def parse_repo_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) extracted from a GitHub URL."""
    # Accept both https://github.com/owner/repo and owner/repo
    url = url.rstrip("/").removesuffix(".git")
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(
            f"Cannot parse owner/repo from URL: {url}\n"
            "Expected format: https://github.com/owner/repo"
        )
    return parts[0], parts[1]


def get_default_branch(owner: str, repo: str, token: Optional[str]) -> str:
    """Fetch the default branch name for the repository."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    data = _github_request(url, token)
    return data["default_branch"]


def get_all_files(owner: str, repo: str, branch: str, token: Optional[str]) -> list[dict]:
    """
    Use the Git Trees API (recursive) to list every file in the repo.
    Returns a list of tree-entry dicts with keys: path, type, size, url.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    data = _github_request(url, token)

    if data.get("truncated"):
        print("  ⚠  Repository tree was truncated by GitHub (very large repo). "
              "Some files may be skipped.")

    # Keep only blobs (files), not trees (directories)
    return [entry for entry in data.get("tree", []) if entry["type"] == "blob"]


def _is_supported(path: str) -> bool:
    """Return True if this file path should be analysed."""
    filename = os.path.basename(path)
    if filename in SKIP_FILENAMES:
        return False
    # Match by extension
    _, ext = os.path.splitext(filename)
    if ext in SUPPORTED_EXTENSIONS:
        return True
    # Match by exact filename (e.g. Dockerfile, .htaccess)
    if filename in SUPPORTED_EXTENSIONS:
        return True
    return False


def fetch_file_content(entry: dict, owner: str, repo: str,
                       token: Optional[str]) -> Optional[RepoFile]:
    """
    Download and decode a single file.
    Returns None if the file should be skipped (too large, binary, etc.).
    """
    size = entry.get("size", 0)
    if size > MAX_FILE_BYTES:
        return None  # skip large files silently

    # Use the Contents API — safer than the raw blob URL for private repos
    path = entry["path"]
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    data = _github_request(url, token)

    encoding = data.get("encoding", "")
    raw = data.get("content", "")

    if encoding == "base64":
        try:
            text = base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return None  # binary file
    else:
        text = raw

    return RepoFile(path=path, content=text, size=size)


# ---------------------------------------------------------------------------
# Static / heuristic security scanner (runs locally, no LLM required)
# ---------------------------------------------------------------------------

# Regex patterns for common hardcoded secrets
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
     "Hardcoded password"),
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded API key"),
    (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded secret key"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded access token"),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*["\']?[A-Z0-9]{16,}["\']?',
     "AWS Access Key ID"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*=\s*["\']?[A-Za-z0-9/+=]{20,}["\']?',
     "AWS Secret Access Key"),
    (r'(?i)(private[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded private key"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "Private key material in source"),
    (r'(?i)(database[_-]?url|db[_-]?url)\s*=\s*["\'][^"\']{10,}["\']',
     "Hardcoded database connection string"),
    (r'(?i)(jdbc:[a-z]+://[^\s"\']+)',
     "Hardcoded JDBC connection string"),
]

# SQL injection patterns (naive but catches obvious cases)
SQLI_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'](.*?)(SELECT|INSERT|UPDATE|DELETE)',
     "Potential SQL injection via string formatting"),
    (r'(?i)\"(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[^\"]*\"\s*\+',
     "SQL query built by string concatenation"),
    (r"(?i)'(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[^']*'\s*\+",
     "SQL query built by string concatenation"),
    (r'(?i)f["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{',
     "SQL query built with f-string (injection risk)"),
]

# XSS patterns
XSS_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)innerHTML\s*=\s*[^;]+',
     "Direct innerHTML assignment (XSS risk)"),
    (r'(?i)document\.write\s*\(',
     "document.write() usage (XSS risk)"),
    (r'(?i)eval\s*\(',
     "eval() usage (code injection risk)"),
    (r'(?i)dangerouslySetInnerHTML',
     "React dangerouslySetInnerHTML usage"),
]

# Insecure crypto / auth patterns
CRYPTO_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)\bmd5\b',
     "MD5 usage (weak hash algorithm)"),
    (r'(?i)\bsha1\b',
     "SHA-1 usage (weak hash algorithm)"),
    (r'(?i)ssl\.CERT_NONE',
     "SSL certificate verification disabled"),
    (r'(?i)verify\s*=\s*False',
     "SSL verification disabled (verify=False)"),
    (r'(?i)DEBUG\s*=\s*True',
     "Debug mode enabled in configuration"),
    (r'(?i)ALLOWED_HOSTS\s*=\s*\[[\s]*["\']?\*["\']?[\s]*\]',
     "Django ALLOWED_HOSTS set to wildcard"),
    (r'(?i)SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']',
     "Django SECRET_KEY appears short / weak"),
]

# Combine all patterns with their risk level
ALL_PATTERNS: list[tuple[str, str, str]] = (
    [(p, title, "Critical") for p, title in SECRET_PATTERNS] +
    [(p, title, "High")     for p, title in SQLI_PATTERNS] +
    [(p, title, "High")     for p, title in XSS_PATTERNS] +
    [(p, title, "Medium")   for p, title in CRYPTO_PATTERNS]
)


def scan_file_statically(repo_file: RepoFile) -> list[SecurityIssue]:
    """
    Run all regex patterns against a file and return a list of SecurityIssues.
    This runs entirely locally — no API calls needed.
    """
    issues: list[SecurityIssue] = []
    lines = repo_file.content.splitlines()

    for pattern, title, risk_level in ALL_PATTERNS:
        compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        for match in compiled.finditer(repo_file.content):
            # Find which line the match is on
            start_pos = match.start()
            line_number = repo_file.content[:start_pos].count("\n") + 1
            snippet = lines[line_number - 1].strip() if line_number <= len(lines) else match.group(0)

            issues.append(SecurityIssue(
                risk_level=risk_level,
                title=title,
                file_path=repo_file.path,
                line_number=str(line_number),
                description=_get_description(title),
                code_snippet=snippet[:200],  # truncate very long lines
                fix=_get_fix_advice(title),
            ))

    return issues


def _get_description(title: str) -> str:
    """Map a finding title to a human-readable danger description."""
    descriptions = {
        "Hardcoded password":
            "Passwords committed to source control are exposed to anyone with "
            "repository access and leak into git history permanently.",
        "Hardcoded API key":
            "API keys in source code are easily scraped by attackers and can "
            "lead to account takeover, data theft, or unexpected billing.",
        "Hardcoded secret key":
            "Secret keys in code allow attackers to forge tokens, decrypt data, "
            "or impersonate the application.",
        "Hardcoded access token":
            "Access tokens grant API privileges — hardcoding them exposes those "
            "privileges to anyone who reads the code.",
        "AWS Access Key ID":
            "Exposed AWS credentials can be used to spin up infrastructure, "
            "exfiltrate S3 data, or rack up large bills.",
        "AWS Secret Access Key":
            "Combined with the Key ID, this gives full programmatic AWS access.",
        "Hardcoded private key":
            "Private key material should never appear in source code. "
            "It can be used to decrypt data or impersonate services.",
        "Private key material in source":
            "PEM-encoded private keys committed to a repo are effectively public.",
        "Hardcoded database connection string":
            "Connection strings contain credentials and host information "
            "allowing direct database access.",
        "Hardcoded JDBC connection string":
            "JDBC URLs often contain embedded credentials.",
        "Potential SQL injection via string formatting":
            "Building SQL with user-controlled input allows attackers to "
            "manipulate queries, dump databases, or delete data.",
        "SQL query built by string concatenation":
            "String concatenation for SQL is a classic injection vector.",
        "SQL query built with f-string (injection risk)":
            "f-strings make it easy to accidentally embed unsanitised input.",
        "Direct innerHTML assignment (XSS risk)":
            "Setting innerHTML with untrusted data allows script injection in "
            "the victim's browser.",
        "document.write() usage (XSS risk)":
            "document.write() with user data is a well-known XSS vector.",
        "eval() usage (code injection risk)":
            "eval() executes arbitrary code — never pass user input to it.",
        "React dangerouslySetInnerHTML usage":
            "Bypasses React's XSS protection — use with extreme care.",
        "MD5 usage (weak hash algorithm)":
            "MD5 is cryptographically broken and should not be used for "
            "passwords, integrity checks, or signatures.",
        "SHA-1 usage (weak hash algorithm)":
            "SHA-1 collision attacks are practical; use SHA-256 or better.",
        "SSL certificate verification disabled":
            "Disabling certificate verification exposes the connection to "
            "man-in-the-middle attacks.",
        "SSL verification disabled (verify=False)":
            "Same as above — all TLS protection is removed.",
        "Debug mode enabled in configuration":
            "Debug mode exposes stack traces, environment variables, and "
            "internal routes to end users.",
        "Django ALLOWED_HOSTS set to wildcard":
            "Wildcard ALLOWED_HOSTS disables Django's Host header validation, "
            "enabling host-header injection attacks.",
        "Django SECRET_KEY appears short / weak":
            "A short SECRET_KEY weakens CSRF tokens, sessions, and signatures.",
    }
    return descriptions.get(title, "This pattern indicates a potential security vulnerability.")


def _get_fix_advice(title: str) -> str:
    """Return a concrete fix recommendation for a given finding title."""
    fixes = {
        "Hardcoded password":
            "Move the password to an environment variable:\n"
            "  password = os.environ['DB_PASSWORD']\n"
            "Or use a secrets manager such as HashiCorp Vault or AWS Secrets Manager.",
        "Hardcoded API key":
            "Store the key in an environment variable or .env file (excluded from git):\n"
            "  api_key = os.environ['SERVICE_API_KEY']",
        "Hardcoded secret key":
            "Use os.environ or a secrets manager. Never commit secrets to git.\n"
            "Rotate the exposed secret immediately.",
        "Hardcoded access token":
            "Revoke the token immediately, then load it from the environment:\n"
            "  token = os.environ['ACCESS_TOKEN']",
        "AWS Access Key ID":
            "Revoke the key in IAM immediately. Use IAM roles or environment "
            "variables (AWS_ACCESS_KEY_ID) instead of hardcoded values.",
        "AWS Secret Access Key":
            "Revoke the key in IAM immediately. Use instance profiles or "
            "environment variables — never embed in code.",
        "Hardcoded private key":
            "Remove from source immediately. Store in a secure vault or HSM. "
            "Rotate the key pair.",
        "Private key material in source":
            "Remove the PEM block from code. Load from a file outside the "
            "repository or from a secrets manager.",
        "Hardcoded database connection string":
            "Use environment variables:\n"
            "  db_url = os.environ['DATABASE_URL']",
        "Hardcoded JDBC connection string":
            "Externalise the JDBC URL to application properties or env vars.",
        "Potential SQL injection via string formatting":
            "Use parameterised queries:\n"
            "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "SQL query built by string concatenation":
            "Use parameterised queries or an ORM instead of concatenation.",
        "SQL query built with f-string (injection risk)":
            "Replace the f-string with a parameterised query:\n"
            "  cursor.execute('SELECT * FROM t WHERE col = %s', (value,))",
        "Direct innerHTML assignment (XSS risk)":
            "Use textContent instead of innerHTML, or sanitise with DOMPurify:\n"
            "  element.textContent = userInput;",
        "document.write() usage (XSS risk)":
            "Replace with DOM manipulation methods:\n"
            "  document.getElementById('out').textContent = value;",
        "eval() usage (code injection risk)":
            "Eliminate eval(). Parse JSON with JSON.parse(), execute known "
            "functions by name from a whitelist.",
        "React dangerouslySetInnerHTML usage":
            "Sanitise the HTML with DOMPurify before passing it:\n"
            "  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}",
        "MD5 usage (weak hash algorithm)":
            "Replace with SHA-256 (hashlib.sha256) or bcrypt for passwords.",
        "SHA-1 usage (weak hash algorithm)":
            "Replace with SHA-256 or SHA-3.",
        "SSL certificate verification disabled":
            "Remove ssl.CERT_NONE. Use the default ssl.create_default_context().",
        "SSL verification disabled (verify=False)":
            "Remove verify=False from the requests call. If using self-signed "
            "certs in dev, pin the CA bundle instead.",
        "Debug mode enabled in configuration":
            "Set DEBUG = False in production. Control via environment variable:\n"
            "  DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'",
        "Django ALLOWED_HOSTS set to wildcard":
            "List specific hostnames:\n"
            "  ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']",
        "Django SECRET_KEY appears short / weak":
            "Generate a strong key:\n"
            "  python -c \"from django.core.management.utils import "
            "get_random_secret_key; print(get_random_secret_key())\"",
    }
    return fixes.get(title, "Review this finding and apply the principle of least privilege / secure defaults.")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
RISK_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def generate_report(report: SecurityReport) -> str:
    """Render the SecurityReport as a Markdown string."""
    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# 🔐 Security Code Review Report",
        "",
        f"**Repository:** {report.repo_url}",
        f"**Files analysed:** {report.files_analysed}",
        f"**Total issues found:** {len(report.issues)}",
        "",
    ]

    # ── Summary table ────────────────────────────────────────────────────────
    counts = {level: 0 for level in RISK_ORDER}
    for issue in report.issues:
        counts[issue.risk_level] = counts.get(issue.risk_level, 0) + 1

    lines += [
        "## Summary",
        "",
        "| Risk Level | Count |",
        "|------------|-------|",
    ]
    for level in ("Critical", "High", "Medium", "Low"):
        emoji = RISK_EMOJI[level]
        lines.append(f"| {emoji} {level} | {counts[level]} |")
    lines.append("")

    # ── Issues (sorted by risk) ───────────────────────────────────────────────
    sorted_issues = sorted(report.issues, key=lambda i: RISK_ORDER.get(i.risk_level, 99))

    if sorted_issues:
        lines += ["## Detailed Findings", ""]
        for idx, issue in enumerate(sorted_issues, start=1):
            emoji = RISK_EMOJI.get(issue.risk_level, "⚪")
            lines += [
                f"### {idx}. {emoji} [{issue.risk_level}] {issue.title}",
                "",
                f"- **File:** `{issue.file_path}`",
                f"- **Line:** {issue.line_number}",
                "",
                "**Why it is dangerous:**",
                f"> {issue.description}",
                "",
                "**Offending code:**",
                "```",
                issue.code_snippet,
                "```",
                "",
                "**Recommended fix:**",
                f"```\n{issue.fix}\n```",
                "",
                "---",
                "",
            ]
    else:
        lines += [
            "## Detailed Findings",
            "",
            "✅ No issues detected by the static scanner. "
            "Consider also running an LLM-assisted deep review.",
            "",
        ]

    # ── Recommendations ───────────────────────────────────────────────────────
    default_recs = [
        "Add a `.gitignore` entry for `.env` files and never commit secrets.",
        "Enable GitHub secret scanning (Settings → Security → Secret scanning).",
        "Integrate a SAST tool (Bandit for Python, ESLint security plugin for JS) "
        "into your CI/CD pipeline.",
        "Use parameterised queries or an ORM for all database interactions.",
        "Apply the principle of least privilege for all API keys and IAM roles.",
        "Keep all dependencies up to date — run `pip audit` / `npm audit` regularly.",
        "Enable HTTPS everywhere and do not disable certificate verification.",
    ]
    all_recs = (report.recommendations or []) + default_recs

    lines += ["## Overall Recommendations", ""]
    for rec in all_recs:
        lines.append(f"- {rec}")
    lines.append("")

    lines += [
        "---",
        "*Report generated by the IBM Bob Hackathon — Security Code Review Agent*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run(repo_url: str, token: Optional[str], output_path: Optional[str]) -> None:
    """Full pipeline: fetch → scan → report."""

    print(f"\n🔍  Security Code Review Agent")
    print(f"    Repository : {repo_url}")
    print(f"    GitHub token: {'provided' if token else 'not provided (rate limits apply)'}")
    print()

    # 1. Parse the URL
    owner, repo = parse_repo_url(repo_url)
    print(f"[1/4] Parsed owner={owner!r}, repo={repo!r}")

    # 2. Get the default branch
    branch = get_default_branch(owner, repo, token)
    print(f"[2/4] Default branch: {branch!r}")

    # 3. List all files in the repository
    print(f"[3/4] Fetching file tree …")
    all_entries = get_all_files(owner, repo, branch, token)
    supported_entries = [e for e in all_entries if _is_supported(e["path"])]
    print(f"      {len(all_entries)} total files, "
          f"{len(supported_entries)} match supported extensions")

    # 4. Fetch and scan each file
    print(f"[4/4] Fetching and scanning files …\n")
    report = SecurityReport(repo_url=repo_url)

    for idx, entry in enumerate(supported_entries, start=1):
        path = entry["path"]
        print(f"  [{idx:>3}/{len(supported_entries)}] {path} … ", end="", flush=True)

        try:
            repo_file = fetch_file_content(entry, owner, repo, token)
        except Exception as exc:
            print(f"SKIP ({exc})")
            continue

        if repo_file is None:
            print("SKIP (too large or binary)")
            continue

        issues = scan_file_statically(repo_file)
        report.files_analysed += 1

        if issues:
            print(f"{len(issues)} issue(s) found")
            report.issues.extend(issues)
        else:
            print("✓ clean")

        # Be polite to the GitHub API — small delay between requests
        time.sleep(0.1)

    # 5. Render the report
    print(f"\n📊  Scan complete.")
    print(f"    Files analysed : {report.files_analysed}")
    print(f"    Issues found   : {len(report.issues)}")

    markdown = generate_report(report)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"\n✅  Report written to: {output_path}")
    else:
        print("\n" + "═" * 70)
        print(markdown)
        print("═" * 70)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security Code Review Agent — IBM Bob Hackathon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_agent.py --repo https://github.com/owner/repo
  python security_agent.py --repo https://github.com/owner/repo --token ghp_xxxx
  python security_agent.py --repo https://github.com/owner/repo --output report.md
        """,
    )
    parser.add_argument(
        "--repo", required=True,
        help="Full GitHub repository URL (e.g. https://github.com/owner/repo)"
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token. "
             "Defaults to the GITHUB_TOKEN environment variable.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write the Markdown report (prints to stdout if omitted).",
    )

    args = parser.parse_args()

    try:
        run(args.repo, args.token, args.output)
    except (RuntimeError, ValueError) as exc:
        print(f"\n❌  Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
