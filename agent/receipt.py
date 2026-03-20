"""
Receipt module for AuditAgent.
Mints on-chain audit receipts via Synthesis ERC-8004 API.
"""
import os
import json
import logging
import hashlib
import requests
from typing import Optional, Dict
from datetime import datetime

logger = logging.getLogger(__name__)

# Synthesis API endpoint
SYNTHESIS_API_BASE = "https://api.synthesis.gg/v1"
SYNTHESIS_API_KEY = os.environ.get("SYNTHESIS_API_KEY")


def mint_receipt(
    audit_hash: str,
    repo_name: str,
    timestamp: str,
    severity_summary: Dict[str, int],
    github_issue_url: Optional[str] = None,
    api_key: Optional[str] = None
) -> Dict:
    """
    Mint an on-chain audit receipt via Synthesis ERC-8004 API.
    
    Args:
        audit_hash: Unique hash of the audit
        repo_name: Name of the audited repository
        timestamp: ISO timestamp of the audit
        severity_summary: Dict with severity counts
        github_issue_url: URL of the GitHub issue (if created)
        api_key: Synthesis API key (uses env var if not provided)
        
    Returns:
        Dict with transaction details
    """
    if not api_key:
        api_key = SYNTHESIS_API_KEY
    
    if not api_key:
        raise ValueError("SYNTHESIS_API_KEY not set")
    
    # Prepare payload
    payload = {
        "audit_hash": audit_hash,
        "repo_name": repo_name,
        "timestamp": timestamp,
        "severity_summary": severity_summary,
        "github_issue_url": github_issue_url,
        "chain_id": 1,  # Ethereum mainnet
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    logger.info(f"Minting receipt for {repo_name} (hash: {audit_hash})")
    
    try:
        response = requests.post(
            f"{SYNTHESIS_API_BASE}/erc8004/mint",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Receipt minted successfully: {result.get('transaction_hash', 'N/A')}")
            return {
                "success": True,
                "transaction_hash": result.get("transaction_hash"),
                "token_id": result.get("token_id"),
                "block_number": result.get("block_number"),
                "receipt_url": result.get("receipt_url")
            }
        elif response.status_code == 401:
            raise ValueError("Invalid Synthesis API key")
        else:
            error = response.json().get("error", response.text)
            logger.error(f"Failed to mint receipt: {error}")
            return {
                "success": False,
                "error": error,
                "status_code": response.status_code
            }
            
    except requests.exceptions.Timeout:
        logger.error("Synthesis API request timed out")
        return {
            "success": False,
            "error": "Request timed out"
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Synthesis API request failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


def record_receipt(
    audit_hash: str,
    repo_name: str,
    timestamp: str,
    severity_summary: Dict[str, int],
    github_issue_url: Optional[str] = None
) -> Dict:
    """
    Main entry point for recording an audit receipt.
    
    Args:
        audit_hash: Unique hash of the audit
        repo_name: Name of the audited repository
        timestamp: ISO timestamp of the audit
        severity_summary: Dict with severity counts
        github_issue_url: URL of the GitHub issue (if created)
        
    Returns:
        Dict with receipt details
    """
    try:
        return mint_receipt(
            audit_hash=audit_hash,
            repo_name=repo_name,
            timestamp=timestamp,
            severity_summary=severity_summary,
            github_issue_url=github_issue_url
        )
    except Exception as e:
        logger.error(f"Failed to record receipt: {e}")
        return {
            "success": False,
            "error": str(e)
        }


def check_receipt_status(audit_hash: str, api_key: Optional[str] = None) -> Dict:
    """
    Check the status of a previously minted receipt.
    
    Args:
        audit_hash: Hash of the audit to check
        api_key: Synthesis API key
        
    Returns:
        Dict with receipt status
    """
    if not api_key:
        api_key = SYNTHESIS_API_KEY
    
    if not api_key:
        raise ValueError("SYNTHESIS_API_KEY not set")
    
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    try:
        response = requests.get(
            f"{SYNTHESIS_API_BASE}/erc8004/receipt/{audit_hash}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "success": False,
                "error": f"Status {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test receipt minting
    logging.basicConfig(level=logging.INFO)
    
    api_key = os.environ.get("SYNTHESIS_API_KEY")
    if api_key:
        result = record_receipt(
            audit_hash="test123",
            repo_name="test/repo",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity_summary={"critical": 1, "high": 2, "medium": 5, "low": 10, "informational": 3}
        )
        print(json.dumps(result, indent=2))
    else:
        print("SYNTHESIS_API_KEY not set")
