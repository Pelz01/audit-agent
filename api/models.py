"""
Pydantic models for AuditAgent API.
"""
from typing import Optional, Dict, List
from pydantic import BaseModel, Field
from datetime import datetime


class SeverityBreakdown(BaseModel):
    """Severity breakdown counts for an audit."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational


class AuditRecord(BaseModel):
    """Single audit record stored in the system."""
    id: str = Field(..., description="Unique audit ID (SHA256 hash)")
    repo: str = Field(..., description="Repository name (owner/repo)")
    timestamp: str = Field(..., description="ISO timestamp of the audit")
    severity_summary: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    github_issue_url: Optional[str] = Field(None, description="URL of GitHub issue if filed")
    pr_url: Optional[str] = Field(None, description="URL of PR if opened")
    receipt_tx_hash: Optional[str] = Field(None, description="On-chain receipt transaction hash")
    summary: Optional[str] = Field(None, description="Claude-generated report summary")
    findings: List[Dict] = Field(default_factory=list, description="Detailed findings array")
    status: str = Field(default="completed", description="Audit status: pending, completed, failed")


class AgentStats(BaseModel):
    """Aggregate statistics for the agent."""
    total_audits: int = 0
    total_vulnerabilities: int = 0
    issues_filed: int = 0
    receipts_minted: int = 0
    last_run: Optional[str] = None
    last_audit_repo: Optional[str] = None


class AuditListResponse(BaseModel):
    """Paginated response for audit list."""
    audits: List[AuditRecord]
    total: int
    page: int
    page_size: int
    has_next: bool


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    agent_running: bool
    last_run: Optional[str] = None
    audits_today: int = 0
    uptime_seconds: float = 0