"""
Interpreter module for AuditAgent.
Sends Slither results to Claude API for analysis.
"""
import os
import json
import logging
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# System prompt for Claude to act as a senior security auditor
SYSTEM_PROMPT = """You are a senior smart contract security auditor with 10+ years of experience in DeFi security. 
Your role is to analyze static analysis findings from Slither and provide a structured, actionable security report.

When analyzing findings:
1. Carefully review each finding's severity (Critical, High, Medium, Low, Informational)
2. Group similar issues together
3. Prioritize vulnerabilities that can lead to loss of funds or protocol compromise
4. Provide clear explanations of the risk and potential exploit scenarios
5. Suggest remediation steps where possible

Your output must be a structured JSON report with the following fields:
- audit_hash: A unique hash of this audit
- repo_name: Name of the audited repository
- timestamp: ISO timestamp of the audit
- summary: Brief summary of findings
- severity_breakdown: {critical: count, high: count, medium: count, low: count, informational: count}
- secret_severity_breakdown: {critical: count, high: count, medium: count} for secret findings
- findings: Array of detailed findings, each with:
  - title: Short descriptive title
  - severity: critical/high/medium/low/informational
  - description: What the issue is
  - impact: Potential impact if exploited
  - location: File and line number if available
  - recommendation: How to fix (if applicable)
- secret_findings: Array of secret exposure findings, each with:
  - title: Short descriptive title
  - severity: CRITICAL/HIGH/MEDIUM
  - file: File where secret was found
  - line: Line number (or 0 for whole-file)
  - description: What was exposed
  - evidence: Redacted evidence (first 4 + last 4 chars)
  - recommendation: Remediation steps

Be thorough but concise. Only output valid JSON, no additional text."""


@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    severity: str
    description: str
    impact: str
    location: str
    recommendation: str = ""


@dataclass
class AuditReport:
    """Structured audit report."""
    audit_hash: str
    repo_name: str
    timestamp: str
    summary: str
    severity_breakdown: Dict[str, int]
    findings: List[Dict]
    secret_severity_breakdown: Dict[str, int] = None
    secret_findings: List[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @property
    def critical_count(self) -> int:
        return self.severity_breakdown.get("critical", 0)
    
    @property
    def high_count(self) -> int:
        return self.severity_breakdown.get("high", 0)
    
    @property
    def medium_count(self) -> int:
        return self.severity_breakdown.get("medium", 0)
    
    @property
    def low_count(self) -> int:
        return self.severity_breakdown.get("low", 0)
    
    @property
    def secret_critical_count(self) -> int:
        return (self.secret_severity_breakdown or {}).get("critical", 0)
    
    @property
    def secret_high_count(self) -> int:
        return (self.secret_severity_breakdown or {}).get("high", 0)
    
    @property
    def secret_medium_count(self) -> int:
        return (self.secret_severity_breakdown or {}).get("medium", 0)
    
    @property
    def has_critical_or_high(self) -> bool:
        return self.critical_count > 0 or self.high_count > 0
    
    @property
    def has_secrets(self) -> bool:
        return self.secret_critical_count > 0 or self.secret_high_count > 0


def generate_audit_hash(repo_name: str, timestamp: str, findings: List) -> str:
    """Generate a unique hash for this audit."""
    data = f"{repo_name}:{timestamp}:{len(findings)}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def call_claude_api(slither_results: Dict, repo_name: str, api_key: str, secret_findings: List = None) -> AuditReport:
    """
    Send Slither results to Claude API for interpretation.
    
    Args:
        slither_results: Raw Slither JSON output
        repo_name: Name of the repository
        api_key: Anthropic API key
        secret_findings: List of secret scanner findings
        
    Returns:
        Structured AuditReport
    """
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package not installed. Run: pip install anthropic")
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Build the user message
    user_message = f"""Analyze the following Slither static analysis results for repository: {repo_name}

Slither Results:
{json.dumps(slither_results, indent=2)}
"""
    
    # Add secret findings if present
    if secret_findings:
        user_message += f"""

Additionally, the following secret exposure findings were detected in non-contract files:

{json.dumps(secret_findings, indent=2)}

Include these in your report under a separate "Secret Exposures" section. Treat CRITICAL secret findings with the same urgency as CRITICAL smart contract vulnerabilities. These require immediate action.
"""

    user_message += "\n\nProvide a structured security audit report in JSON format."

    logger.info(f"Sending {len(slither_results.get('results', []))} findings to Claude API")
    
    try:
        client = anthropic.Anthropic(api_key=api_key)
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": user_message}
            ]
        )
        
        # Parse the JSON response
        response_text = response.content[0].text
        
        # Try to extract JSON from response
        try:
            report_data = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                report_data = json.loads(json_match.group())
            else:
                raise ValueError("Could not parse JSON from Claude response")
        
        # Ensure required fields
        report_data["repo_name"] = repo_name
        report_data["timestamp"] = timestamp
        if "audit_hash" not in report_data:
            report_data["audit_hash"] = generate_audit_hash(
                repo_name, 
                timestamp, 
                report_data.get("findings", [])
            )
        
        # Ensure severity_breakdown exists
        if "severity_breakdown" not in report_data:
            report_data["severity_breakdown"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
            for finding in report_data.get("findings", []):
                sev = finding.get("severity", "informational").lower()
                if sev in report_data["severity_breakdown"]:
                    report_data["severity_breakdown"][sev] += 1
        
        return AuditReport(**report_data)
        
    except Exception as e:
        logger.error(f"Claude API error: {e}")
        # Return a minimal report on error
        return AuditReport(
            audit_hash=generate_audit_hash(repo_name, timestamp, []),
            repo_name=repo_name,
            timestamp=timestamp,
            summary=f"Failed to analyze with Claude: {str(e)}",
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
            findings=[]
        )


def interpret_results(slither_results: Dict, repo_name: str, secret_findings: List = None) -> AuditReport:
    """
    Interpret Slither results using Claude API.
    
    Args:
        slither_results: Raw Slither JSON output
        repo_name: Name of the repository
        secret_findings: List of secret scanner findings
        
    Returns:
        Structured AuditReport
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")
    
    return call_claude_api(slither_results, repo_name, api_key, secret_findings)


if __name__ == "__main__":
    # Test interpretation
    logging.basicConfig(level=logging.INFO)
    
    # Sample Slither results for testing
    sample_results = {
        "success": True,
        "results": [
            {
                "check": "tx-origin",
                "description": "Use of tx.origin",
                "severity": "Medium",
                "confidence": "high",
                "elements": [
                    {
                        "type": "function",
                        "name": "transfer",
                        "source_mapping": {"filename": "Token.sol", "lines": [45]}
                    }
                ]
            }
        ]
    }
    
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        report = interpret_results(sample_results, "test/repo")
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("ANTHROPIC_API_KEY not set")
