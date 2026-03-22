"""
JSON file storage for AuditAgent.
Reads/writes audit records to the audits/ directory.
"""
import os
import json
import logging
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from pathlib import Path

from .models import AuditRecord, SeverityBreakdown, AgentStats

logger = logging.getLogger(__name__)

# Storage directory
STORAGE_DIR = Path(__file__).parent.parent / "audits"
STORAGE_DIR.mkdir(exist_ok=True)


def _get_audit_file(audit_id: str) -> Path:
    """Get the file path for an audit record."""
    return STORAGE_DIR / f"{audit_id}.json"


def save_audit(audit: AuditRecord) -> bool:
    """
    Save an audit record to disk.
    
    Args:
        audit: AuditRecord to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        file_path = _get_audit_file(audit.id)
        with open(file_path, "w") as f:
            json.dump(audit.model_dump(mode="json"), f, indent=2)
        logger.info(f"Saved audit {audit.id} for {audit.repo}")
        return True
    except Exception as e:
        logger.error(f"Failed to save audit {audit.id}: {e}")
        return False


def get_audit(audit_id: str) -> Optional[AuditRecord]:
    """
    Retrieve a single audit by ID.
    
    Args:
        audit_id: ID of the audit to retrieve
        
    Returns:
        AuditRecord if found, None otherwise
    """
    try:
        file_path = _get_audit_file(audit_id)
        if not file_path.exists():
            return None
        with open(file_path, "r") as f:
            data = json.load(f)
        return AuditRecord(**data)
    except Exception as e:
        logger.error(f"Failed to read audit {audit_id}: {e}")
        return None


def list_audits(page: int = 1, page_size: int = 10) -> Dict:
    """
    List all audits with pagination.
    
    Args:
        page: Page number (1-indexed)
        page_size: Number of audits per page
        
    Returns:
        Dict with audits, total count, and pagination info
    """
    try:
        # Get all audit files
        audit_files = sorted(
            STORAGE_DIR.glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        
        total = len(audit_files)
        start = (page - 1) * page_size
        end = start + page_size
        page_files = audit_files[start:end]
        
        audits = []
        for file_path in page_files:
            if file_path.name == "seen_repos.json":
                continue
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                audits.append(AuditRecord(**data))
            except Exception as e:
                logger.warning(f"Failed to load {file_path.name}: {e}")
                continue
        
        return {
            "audits": audits,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_next": end < total
        }
    except Exception as e:
        logger.error(f"Failed to list audits: {e}")
        return {
            "audits": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "has_next": False
        }


def get_stats() -> AgentStats:
    """
    Get aggregate statistics across all audits.
    
    Returns:
        AgentStats with aggregated data
    """
    try:
        audit_files = list(STORAGE_DIR.glob("*.json"))
        
        total_audits = len(audit_files)
        total_vulnerabilities = 0
        issues_filed = 0
        receipts_minted = 0
        last_run = None
        last_audit_repo = None
        
        for file_path in audit_files:
            if file_path.name == "seen_repos.json":
                continue
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                
                # Sum vulnerabilities
                severity = data.get("severity_summary", {})
                total_vulnerabilities += (
                    severity.get("critical", 0) +
                    severity.get("high", 0) +
                    severity.get("medium", 0) +
                    severity.get("low", 0) +
                    severity.get("informational", 0)
                )
                
                # Count issues filed
                if data.get("github_issue_url"):
                    issues_filed += 1
                
                # Count receipts minted
                if data.get("receipt_tx_hash"):
                    receipts_minted += 1
                
                # Track most recent
                timestamp = data.get("timestamp", "")
                if not last_run or timestamp > last_run:
                    last_run = timestamp
                    last_audit_repo = data.get("repo")
                    
            except Exception as e:
                logger.warning(f"Failed to process {file_path.name}: {e}")
                continue
        
        return AgentStats(
            total_audits=total_audits,
            total_vulnerabilities=total_vulnerabilities,
            issues_filed=issues_filed,
            receipts_minted=receipts_minted,
            last_run=last_run,
            last_audit_repo=last_audit_repo
        )
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return AgentStats()


def get_audits_today() -> int:
    """
    Get count of audits run today.
    
    Returns:
        Number of audits run today
    """
    try:
        today = datetime.now().date()
        count = 0
        
        for file_path in STORAGE_DIR.glob("*.json"):
            if file_path.name == "seen_repos.json":
                continue
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                audit_date = datetime.fromisoformat(
                    data.get("timestamp", "").replace("Z", "+00:00")
                ).date()
                if audit_date == today:
                    count += 1
            except:
                continue
        
        return count
    except Exception as e:
        logger.error(f"Failed to count today's audits: {e}")
        return 0


def get_last_audit_time() -> Optional[str]:
    """
    Get timestamp of the most recent audit.
    
    Returns:
        ISO timestamp string or None
    """
    try:
        audit_files = sorted(
            STORAGE_DIR.glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        audit_files = [f for f in audit_files if f.name != "seen_repos.json"]
        if audit_files:
            with open(audit_files[0], "r") as f:
                data = json.load(f)
            return data.get("timestamp")
        return None
    except Exception as e:
        logger.error(f"Failed to get last audit time: {e}")
        return None


if __name__ == "__main__":
    # Test storage functions
    logging.basicConfig(level=logging.INFO)
    
    # List audits
    result = list_audits(page=1, page_size=5)
    print(f"Total audits: {result['total']}")
    print(f"Page 1 audits: {len(result['audits'])}")
    
    # Get stats
    stats = get_stats()
    print(f"Stats: {stats.model_dump()}")
