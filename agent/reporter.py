"""
Reporter module for AuditAgent v2.
Files GitHub issues or opens PRs with fixes for critical findings.
"""
import os
import json
import logging
import time
import requests
from typing import Optional, Dict, List, Any
from datetime import datetime
from github import Github
from github.Issue import Issue

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 1

# GitHub API base
GITHUB_API = "https://api.github.com"


def get_github_headers() -> Dict[str, str]:
    """Get headers for GitHub API."""
    token = os.environ.get("GITHUB_TOKEN")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def get_github_username() -> str:
    """Get the authenticated user's username."""
    token = os.environ.get("GITHUB_TOKEN")
    g = Github(token)
    return g.get_user().login


def extract_critical_vulnerabilities(scan_findings: Dict) -> List[Dict]:
    """Extract critical vulnerabilities from Slither results."""
    critical = []
    for finding in scan_findings.get("results", []):
        severity = finding.get("severity", "").lower()
        if severity == "critical":
            elements = finding.get("elements", [])
            for elem in elements:
                if elem.get("type") == "function":
                    critical.append({
                        "check": finding.get("check", "unknown"),
                        "description": finding.get("description", ""),
                        "severity": severity,
                        "function_name": elem.get("name", "unknown"),
                        "source_mapping": elem.get("source_mapping", {})
                    })
                    break  # Only need one per finding
    return critical[:1]  # Only process first critical for focus


def fetch_file_content(owner: str, repo: str, file_path: str) -> Optional[Dict]:
    """Fetch file content from GitHub."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}"
    response = requests.get(url, headers=get_github_headers())
    
    if response.status_code == 200:
        data = response.json()
        import base64
        content = base64.b64decode(data["content"]).decode("utf-8")
        return {
            "content": content,
            "sha": data["sha"]
        }
    logger.error(f"Failed to fetch {file_path}: {response.status_code}")
    return None


def ask_claude_for_fix(
    file_content: str,
    vulnerability_desc: str,
    function_name: str,
    file_path: str
) -> Optional[str]:
    """Ask Claude to generate a fix for the vulnerability."""
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed")
        return None
    
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not set")
        return None
    
    system_prompt = """You are a smart contract security engineer. You fix Solidity vulnerabilities precisely and minimally. You only change what is necessary to fix the vulnerability. You do not refactor, rename, or restructure anything else. Your fix must be production-safe."""

    user_message = f"""Here is a Solidity file with a vulnerability in the {function_name} function.

Vulnerability: {vulnerability_desc}
File: {file_path}

Original file content:
{file_content}

Return ONLY the complete fixed file content. No explanation. No markdown. No code fences. Just the raw Solidity code."""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )
        
        fixed_content = response.content[0].text
        
        # Remove code fences if present
        if "```" in fixed_content:
            lines = fixed_content.split("\n")
            fixed_content = "\n".join(lines[1:-1] if lines[0].startswith("```") else lines)
            fixed_content = fixed_content.strip()
        
        return fixed_content
        
    except Exception as e:
        logger.error(f"Claude API error: {e}")
        return None


def fork_repository(owner: str, repo: str) -> Optional[str]:
    """Fork a repository."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/forks"
    response = requests.post(url, headers=get_github_headers())
    
    if response.status_code == 202:
        time.sleep(3)  # Wait for fork to be ready
        username = get_github_username()
        return f"{username}/{repo}"
    elif response.status_code == 202:  # Already forked
        username = get_github_username()
        return f"{username}/{repo}"
    
    logger.error(f"Fork failed: {response.status_code} - {response.text}")
    return None


def create_branch(owner: str, repo: str, branch_name: str, base_sha: str) -> bool:
    """Create a new branch."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/refs"
    data = {
        "ref": f"refs/heads/{branch_name}",
        "sha": base_sha
    }
    response = requests.post(url, headers=get_github_headers(), json=data)
    return response.status_code in [200, 201]


def get_default_branch_sha(owner: str, repo: str) -> Optional[str]:
    """Get SHA of the default branch."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    response = requests.get(url, headers=get_github_headers())
    
    if response.status_code == 200:
        return response.json().get("default_branch")
    return None


def push_fix_to_branch(
    owner: str,
    repo: str,
    file_path: str,
    branch: str,
    content: str,
    sha: str
) -> bool:
    """Push the fixed file to a branch."""
    import base64
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}"
    data = {
        "message": f"fix: patch vulnerability in {file_path}\n\nGenerated by AuditAgent — review before merging.",
        "content": base64.b64encode(content.encode()).decode(),
        "sha": sha,
        "branch": branch
    }
    response = requests.put(url, headers=get_github_headers(), json=data)
    return response.status_code in [200, 201]


def open_pull_request(
    owner: str,
    repo: str,
    head_branch: str,
    title: str,
    body: str,
    base_branch: str = "main"
) -> Optional[str]:
    """Open a pull request."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls"
    data = {
        "title": title,
        "body": body,
        "head": head_branch,
        "base": base_branch
    }
    response = requests.post(url, headers=get_github_headers(), json=data)
    
    if response.status_code in [200, 201]:
        return response.json().get("html_url")
    elif response.status_code == 422:  # PR already exists
        # Try to get existing PR
        response = requests.get(url, headers=get_github_headers(), params={"head": head_branch})
        if response.status_code == 200:
            prs = response.json()
            if prs:
                return prs[0].get("html_url")
    
    logger.error(f"PR creation failed: {response.status_code} - {response.text}")
    return None


def file_github_issue(
    token: str,
    repo_name: str,
    report,
    threshold: int = DEFAULT_THRESHOLD
) -> Optional[str]:
    """File a GitHub issue (non-critical flow)."""
    g = Github(token)
    
    try:
        repo = g.get_repo(repo_name)
        critical_high_count = report.critical_count + report.high_count
        
        # Check if issue already exists
        issues = repo.get_issues(state="open")
        audit_hash = report.audit_hash
        
        for issue in issues:
            if audit_hash in issue.body:
                return issue.html_url
        
        title = f"[Security Audit] {report.repo_name} - {critical_high_count} Critical/High Findings"
        body = create_issue_body(report)
        
        issue = repo.create_issue(
            title=title,
            body=body,
            labels=["security", "audit", "automated"]
        )
        
        logger.info(f"Created GitHub issue #{issue.number} for {repo_name}")
        return issue.html_url
        
    except Exception as e:
        logger.error(f"Failed to create GitHub issue: {e}")
        raise


def create_issue_body(report) -> str:
    """Create the GitHub issue body."""
    body = f"""## 🔒 Security Audit Report

**Repository:** {report.repo_name}
**Audit Timestamp:** {report.timestamp}
**Audit Hash:** `{report.audit_hash}`

---

### Summary

{report.summary}

---

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {report.severity_breakdown.get('critical', 0)} |
| High | {report.severity_breakdown.get('high', 0)} |
| Medium | {report.severity_breakdown.get('medium', 0)} |
| Low | {report.severity_breakdown.get('low', 0)} |
| Informational | {report.severity_breakdown.get('informational', 0)} |

---

### Detailed Findings

"""
    
    severity_order = ["critical", "high", "medium", "low", "informational"]
    
    for severity in severity_order:
        severity_findings = [f for f in report.findings if f.get("severity", "").lower() == severity]
        
        if not severity_findings:
            continue
        
        emoji = {
            "critical": "🚨",
            "high": "⚠️", 
            "medium": "⚡",
            "low": "📝",
            "informational": "ℹ️"
        }.get(severity, "•")
        
        body += f"#### {emoji} {severity.upper()} Severity\n\n"
        
        for i, finding in enumerate(severity_findings, 1):
            body += f"**{i}. {finding.get('title', 'Untitled')}**\n\n"
            body += f"- **Description:** {finding.get('description', 'N/A')}\n"
            body += f"- **Impact:** {finding.get('impact', 'N/A')}\n"
            body += f"- **Location:** {finding.get('location', 'N/A')}\n"
            
            if finding.get("recommendation"):
                body += f"- **Recommendation:** {finding.get('recommendation')}\n"
            
            body += "\n"
    
    body += """---

*This issue was automatically generated by AuditAgent.* 
"""
    
    return body


def handle_critical(
    repo_full_name: str,
    audit_report,
    scan_findings: Dict,
    pr_url: str = None,
    issue_url: str = None
) -> Optional[str]:
    """
    Handle critical vulnerabilities - fork, fix, and open PR.
    """
    logger.info(f"[REPORT] Critical findings detected — initiating PR flow for {repo_full_name}")
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN not set")
        return None
    
    owner, repo = repo_full_name.split("/")
    username = get_github_username()
    
    # Extract critical vulnerabilities
    critical_vulns = extract_critical_vulnerabilities(scan_findings)
    
    if not critical_vulns:
        logger.warning("No critical vulnerabilities found to fix")
        return None
    
    vuln = critical_vulns[0]
    vuln_type = vuln.get("check", "unknown")
    function_name = vuln.get("function_name", "unknown")
    source_mapping = vuln.get("source_mapping", {})
    
    # Get file path from source mapping
    file_path = source_mapping.get("filename", "")
    if not file_path:
        logger.warning("No file path found for vulnerability")
        return None
    
    # Fetch original file
    logger.info(f"[REPORT] Fetching vulnerable file: {file_path}")
    file_data = fetch_file_content(owner, repo, file_path)
    
    if not file_data:
        logger.error("Failed to fetch file content, falling back to issue")
        return None
    
    # Ask Claude for fix
    logger.info(f"[REPORT] Generating fix with Claude for {vuln_type}...")
    fixed_content = ask_claude_for_fix(
        file_data["content"],
        vuln.get("description", ""),
        function_name,
        file_path
    )
    
    if not fixed_content:
        logger.error("Fix generation failed, falling back to issue")
        return None
    
    # Fork the repository
    logger.info(f"[REPORT] Forking repository {repo_full_name}...")
    fork_result = fork_repository(owner, repo)
    
    if not fork_result:
        logger.error("Fork failed, falling back to issue")
        return None
    
    fork_owner, fork_repo_name = fork_result.split("/")
    
    # Get default branch SHA
    base_sha = get_default_branch_sha(fork_owner, fork_repo_name)
    if not base_sha:
        logger.error("Failed to get default branch SHA")
        return None
    
    # Create branch
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    branch_name = f"auditAgent/fix-{vuln_type}-{timestamp}"
    
    logger.info(f"[REPORT] Creating branch {branch_name}...")
    if not create_branch(fork_owner, fork_repo_name, branch_name, base_sha):
        # Try with suffix
        branch_name = f"auditAgent/fix-{vuln_type}-{timestamp}-{os.urandom(2).hex()}"
        if not create_branch(fork_owner, fork_repo_name, branch_name, base_sha):
            logger.error("Branch creation failed")
            return None
    
    # Push fix
    logger.info(f"[REPORT] Pushing fix to fork...")
    if not push_fix_to_branch(fork_owner, fork_repo_name, file_path, branch_name, fixed_content, file_data["sha"]):
        logger.error("Push failed")
        return None
    
    # Open PR
    pr_title = f"[AuditAgent] Fix: {vuln_type} vulnerability in {function_name}"
    pr_body = f"""## 🤖 Automated Security Fix by AuditAgent

> **This PR was generated autonomously by [AuditAgent](https://github.com/Pelz01/audit-agent). Review all changes carefully before merging.**

### Vulnerability Fixed
- **Type:** {vuln_type}
- **Severity:** 🚨 CRITICAL
- **Location:** `{file_path}` → `{function_name}()`
- **Description:** {vuln.get('description', '')[:200]}

### What Was Changed
Generated a fix to address the {vuln_type} vulnerability using checks-effects-interactions pattern or appropriate mitigation.

### ⚠️ Important
- This fix was generated by AI. It addresses the identified vulnerability but may have edge cases.
- Run your full test suite before merging.
- Consider having a human security engineer review this change.

---
*Audited by AuditAgent*
"""
    
    logger.info(f"[REPORT] Opening pull request...")
    pr_url = open_pull_request(
        owner, repo,
        f"{username}:{branch_name}",
        pr_title,
        pr_body
    )
    
    if pr_url:
        logger.info(f"[REPORT] PR opened: {pr_url}")
    else:
        logger.error("PR creation failed")
        return None
    
    # File issue on original repo
    issue_body = f"""## 🚨 Critical Vulnerability Detected by AuditAgent

A Critical security vulnerability has been found in this repository during an automated scan.

**A fix has been prepared and submitted as a Pull Request:** {pr_url}

### Vulnerability Summary
| Severity | Type | Location |
|----------|------|----------|
| 🚨 CRITICAL | {vuln_type} | {file_path}:{function_name} |

{audit_report.summary}

---
> 🤖 This is an automated scan by [AuditAgent](https://github.com/Pelz01/audit-agent).
"""
    
    try:
        g = Github(token)
        original_repo = g.get_repo(repo_full_name)
        issue = original_repo.create_issue(
            title=f"[AuditAgent] Critical: {vuln_type} in {repo}",
            body=issue_body,
            labels=["security", "audit", "automated", "critical"]
        )
        issue_url = issue.html_url
        logger.info(f"[REPORT] Issue filed: {issue_url}")
    except Exception as e:
        logger.warning(f"Issue filing failed: {e}")
    
    return pr_url


def handle_non_critical(repo_full_name: str, audit_report) -> Optional[str]:
    """Handle non-critical findings - file issue."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return None
    
    return file_github_issue(token, repo_full_name, audit_report)


def report_findings(
    repo_full_name: str,
    audit_report,
    scan_findings: Dict = None
) -> Optional[str]:
    """
    Main entry point for reporting findings.
    Routes to PR flow for critical contract vulns, issue for secrets + non-critical.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GitHub token is required")
    
    critical_count = audit_report.critical_count if hasattr(audit_report, 'critical_count') else audit_report.severity_breakdown.get('critical', 0)
    high_count = audit_report.high_count if hasattr(audit_report, 'high_count') else audit_report.severity_breakdown.get('high', 0)
    medium_count = audit_report.severity_breakdown.get('medium', 0) if hasattr(audit_report, 'severity_breakdown') else 0
    
    # Check for secret findings
    secret_critical = getattr(audit_report, 'secret_critical_count', 0) or 0
    secret_high = getattr(audit_report, 'secret_high_count', 0) or 0
    secret_findings = getattr(audit_report, 'secret_findings', []) or []
    
    has_secrets = secret_critical > 0 or secret_high > 0
    secret_issue_url = None
    
    # File secret issue if secrets found (secrets get issue, not PR)
    if has_secrets:
        logger.info(f"Secret exposures detected for {repo_full_name}, filing urgent issue")
        secret_issue_url = file_secret_issue(token, repo_full_name, audit_report, secret_findings)
        if secret_issue_url:
            logger.info(f"Secret issue filed: {secret_issue_url}")
    
    # Decision logic: PR for contract criticals, issue otherwise
    if critical_count > 0:
        logger.info(f"Critical contract findings detected for {repo_full_name}")
        return handle_critical(repo_full_name, audit_report, scan_findings or {})
    elif high_count > 0 or medium_count > 0 or (has_secrets and not critical_count):
        logger.info(f"Non-critical findings for {repo_full_name}, filing issue")
        return handle_non_critical(repo_full_name, audit_report)
    elif has_secrets:
        return secret_issue_url
    else:
        logger.info(f"No significant findings for {repo_full_name}")
        return None


# Keep backwards compatible alias
report = report_findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Reporter module loaded.")


def file_secret_issue(
    token: str,
    repo_name: str,
    report,
    secret_findings: List[Dict]
) -> Optional[str]:
    """File a GitHub issue for secret exposures."""
    from github import Github
    
    g = Github(token)
    
    try:
        repo = g.get_repo(repo_name)
        
        # Build secret findings table
        secrets_table = "| Severity | Type | File | Line |\n|----------|------|------|------|\n"
        for s in secret_findings:
            severity = s.get("severity", "UNKNOWN")
            title = s.get("title", "Unknown")
            file = s.get("file", "unknown")
            line = s.get("line", 0)
            secrets_table += f"| 🚨 {severity} | {title} | `{file}` | {line} |\n"
        
        body = f"""## 🚨 URGENT — Secrets Detected in Repository

**Immediate action required.** Exposed credentials were found in this repository.
Rotating keys should be done within the next hour if the repository is public.

### ⚡ Immediate Steps
1. **Rotate all exposed credentials NOW** — assume they are already compromised
2. **Remove secrets from git history** using [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) or `git filter-repo`
3. **Add `.env` to `.gitignore`** if not already present
4. **Enable GitHub Secret Scanning** in your repository settings

### Exposed Secrets Found

{secrets_table}
---
> 🤖 Scanned by [AuditAgent](https://github.com/Pelz01/audit-agent)
"""
        
        issue = repo.create_issue(
            title=f"[AuditAgent] 🚨 URGENT: Secrets Exposed in {repo_name.split('/')[1]}",
            body=body,
            labels=["security", "urgent", "secrets"]
        )
        
        logger.info(f"Created secret issue #{issue.number} for {repo_name}")
        return issue.html_url
        
    except Exception as e:
        logger.error(f"Failed to create secret issue: {e}")
        return None
