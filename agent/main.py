"""
Main orchestrator for AuditAgent v2.
Runs the full Discover→Scan→Interpret→Act→Receipt loop on a schedule.
"""
import os
import sys
import json
import logging
import asyncio
import schedule
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("audit_agent.log")
    ]
)
logger = logging.getLogger(__name__)

# Import agent modules
from agent.discovery import discover_solidity_repos, rank_repos
from agent.scanner import scan_repository
from agent.interpreter import interpret_results, AuditReport
from agent.reporter import report_findings
from agent.receipt import record_receipt

# For saving audits
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from api.models import AuditRecord, SeverityBreakdown
from api import storage


class AuditAgent:
    """
    Main AuditAgent orchestrator.
    Coordinates discovery, scanning, interpretation, reporting, and receipt minting.
    """
    
    def __init__(
        self,
        github_token: str,
        pollinations_api_key: str,
        synthesis_api_key: str,
        interval_hours: int = 6,
        max_results: int = 10,
        issue_threshold: int = 1
    ):
        self.github_token = github_token
        self.pollinations_api_key = pollinations_api_key
        self.synthesis_api_key = synthesis_api_key
        self.interval_hours = interval_hours
        self.max_results = max_results
        self.issue_threshold = issue_threshold
        
        os.environ["GITHUB_TOKEN"] = github_token
        os.environ["POLLINATIONS_API_KEY"] = pollinations_api_key
        os.environ["SYNTHESIS_API_KEY"] = synthesis_api_key
        
        logger.info(f"AuditAgent initialized. Running every {interval_hours} hours.")
    
    def run_audit_cycle(self, repo_override: str = None) -> Dict:
        """
        Run a single audit cycle.
        
        Args:
            repo_override: If provided, audit this specific repo instead of discovering
        """
        cycle_start = datetime.now()
        results = {
            "cycle_start": cycle_start.isoformat(),
            "repos_discovered": 0,
            "repos_scanned": 0,
            "repos_with_findings": 0,
            "issues_filed": 0,
            "receipts_minted": 0,
            "errors": []
        }
        
        log_broadcast("[DISCOVERY] Starting audit cycle...")
        
        try:
            # Step 1: Discover or use override
            if repo_override:
                log_broadcast(f"[DISCOVERY] On-demand audit requested: {repo_override}")
                repos = [{"name": repo_override, "clone_url": f"https://github.com/{repo_override}.git", "default_branch": "main"}]
            else:
                log_broadcast("[DISCOVERY] Searching GitHub for Solidity repositories...")
                repos = discover_solidity_repos(
                    self.github_token,
                    max_results=self.max_results
                )
            
            if not repos:
                log_broadcast("[DISCOVERY] No repositories found")
                results["repos_discovered"] = 0
                return results
            
            ranked_repos = rank_repos(repos)
            results["repos_discovered"] = len(ranked_repos)
            log_broadcast(f"[DISCOVERY] Found {len(ranked_repos)} candidate(s)")
            
            # Process each repository
            for repo in ranked_repos:
                try:
                    repo_name = repo['name']
                    log_broadcast(f"\n[SCAN] Auditing {repo_name}...")
                    
                    # Step 2: Scan
                    log_broadcast(f"[SCAN] Cloning {repo_name}...")
                    scan_results = scan_repository(
                        repo['clone_url'],
                        branch=repo.get('default_branch', 'main')
                    )
                    results["repos_scanned"] += 1
                    
                    if not scan_results.get("success"):
                        log_broadcast(f"[ERROR] Scan failed: {scan_results.get('error')}")
                        results["errors"].append({
                            "repo": repo_name,
                            "error": scan_results.get("error")
                        })
                        continue
                    
                    finding_count = len(scan_results.get("results", []))
                    log_broadcast(f"[SCAN] Slither complete: {finding_count} findings detected")
                    
                    if not scan_results.get("results"):
                        log_broadcast(f"[SCAN] No findings in {repo_name}")
                        continue
                    
                    # Step 3: Interpret
                    log_broadcast("[INTERPRET] Sending findings to Pollinations...")
                    report = interpret_results(scan_results, repo_name, scan_results.get("secrets", []))
                    
                    critical = report.critical_count
                    high = report.high_count
                    medium = report.medium_count
                    low = report.low_count
                    
                    log_broadcast(f"[INTERPRET] Report generated: {critical} Critical, {high} High, {medium} Medium, {low} Low")
                    
                    if report.has_critical_or_high:
                        results["repos_with_findings"] += 1
                        
                        # Step 4: Report
                        if critical > 0:
                            log_broadcast("[REPORT] Critical findings detected — initiating PR flow")
                        else:
                            log_broadcast("[REPORT] High/Medium findings — filing issue")
                        
                        issue_url = report_findings(
                            repo_name,
                            report,
                            scan_results,
                            issue_threshold=self.issue_threshold
                        )
                        
                        if issue_url:
                            log_broadcast(f"[REPORT] Action completed: {issue_url}")
                            results["issues_filed"] += 1
                        
                        # Step 5: Receipt
                        log_broadcast("[RECEIPT] Minting on-chain receipt...")
                        receipt = record_receipt(
                            audit_hash=report.audit_hash,
                            repo_name=report.repo_name,
                            timestamp=report.timestamp,
                            severity_summary=report.severity_breakdown,
                            github_issue_url=issue_url
                        )
                        
                        if receipt.get("success"):
                            tx_hash = receipt.get("transaction_hash", "")
                            log_broadcast(f"[RECEIPT] Receipt minted: {tx_hash[:20]}...")
                            results["receipts_minted"] += 1
                        else:
                            log_broadcast(f"[WARNING] Receipt failed: {receipt.get('error')}")
                    else:
                        # No critical/high - still save the audit
                        issue_url = None
                        receipt = {"success": False}
                    
                    # Save audit record
                    try:
                        severity = SeverityBreakdown(
                            critical=report.critical_count,
                            high=report.high_count,
                            medium=report.medium_count,
                            low=report.low_count,
                            informational=len([f for f in report.findings if f.get("severity", "").lower() == "informational"])
                        )
                        audit_record = AuditRecord(
                            id=report.audit_hash,
                            repo=report.repo_name,
                            timestamp=report.timestamp,
                            severity_summary=severity,
                            github_issue_url=issue_url,
                            receipt_tx_hash=receipt.get("transaction_hash") if receipt.get("success") else None,
                            summary=report.summary,
                            findings=report.findings,
                            status="completed"
                        )
                        storage.save_audit(audit_record)
                        log_broadcast(f"[DISCOVERY] Audit saved: {report.audit_hash}")
                    except Exception as save_err:
                        log_broadcast(f"[ERROR] Failed to save audit: {save_err}")
                    
                except Exception as e:
                    log_broadcast(f"[ERROR] Error auditing {repo.get('name')}: {e}")
                    results["errors"].append({
                        "repo": repo.get("name"),
                        "error": str(e)
                    })
                    continue
            
        except Exception as e:
            log_broadcast(f"[ERROR] Critical error in audit cycle: {e}")
            results["errors"].append({"cycle_error": str(e)})
        
        cycle_end = datetime.now()
        results["cycle_end"] = cycle_end.isoformat()
        results["duration_seconds"] = (cycle_end - cycle_start).total_seconds()
        
        log_broadcast(f"[DONE] Audit complete: {results['repos_scanned']} scanned, {results['issues_filed']} actions, {results['receipts_minted']} receipts")
        
        return results
    
    def run_continuously(self):
        """Run audit cycles on a schedule."""
        self.run_audit_cycle()
        
        schedule.every(self.interval_hours).hours.do(self.run_audit_cycle)
        
        logger.info(f"Next audit in {self.interval_hours} hours")
        
        while True:
            schedule.run_pending()
            time.sleep(60)
    
    def run_once(self, repo_override: str = None):
        """Run a single audit cycle."""
        return self.run_audit_cycle(repo_override=repo_override)


def log_broadcast(message: str):
    """Log and broadcast to WebSocket if available."""
    logger.info(message)
    
    # Try to import and use broadcast_log from server
    try:
        from api.server import broadcast_log
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcast_log(message), loop)
        else:
            loop.run_until_complete(broadcast_log(message))
    except Exception:
        pass  # never crash the agent because of a log failure


def audit_cycle(repo_override: str = None):
    """Compatibility helper for import verification."""
    return AuditAgent


def start_api_server():
    """Start the FastAPI server."""
    import uvicorn
    from api.server import app
    
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)


def main():
    """Main entry point."""
    github_token = os.environ.get("GITHUB_TOKEN")
    pollinations_api_key = os.environ.get("POLLINATIONS_API_KEY")
    synthesis_api_key = os.environ.get("SYNTHESIS_API_KEY")
    
    # Start API server if RUN_API=true
    if os.environ.get("RUN_API", "false").lower() == "true":
        from threading import Thread
        api_thread = Thread(target=start_api_server, daemon=True)
        api_thread.start()
        logging.info("FastAPI server started on port {}".format(os.environ.get("PORT", 8000)))
    
    missing = []
    if not github_token:
        missing.append("GITHUB_TOKEN")
    if not pollinations_api_key:
        missing.append("POLLINATIONS_API_KEY")
    if not synthesis_api_key:
        missing.append("SYNTHESIS_API_KEY")
    
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)
    
    interval_hours = int(os.environ.get("AUDIT_INTERVAL_HOURS", "6"))
    max_results = int(os.environ.get("AUDIT_MAX_RESULTS", "10"))
    issue_threshold = int(os.environ.get("AUDIT_ISSUE_THRESHOLD", "1"))
    
    agent = AuditAgent(
        github_token=github_token,
        pollinations_api_key=pollinations_api_key,
        synthesis_api_key=synthesis_api_key,
        interval_hours=interval_hours,
        max_results=max_results,
        issue_threshold=issue_threshold
    )
    
    if os.environ.get("AUDIT_DAEMON", "true").lower() == "true":
        agent.run_continuously()
    else:
        results = agent.run_once()
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
