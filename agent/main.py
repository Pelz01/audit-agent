"""
Main orchestrator for AuditAgent.
Runs the full Discover→Scan→Interpret→Act→Receipt loop on a schedule.
"""
import os
import sys
import json
import logging
import schedule
import time
import threading
from datetime import datetime
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


class AuditAgent:
    """
    Main AuditAgent orchestrator.
    Coordinates discovery, scanning, interpretation, reporting, and receipt minting.
    """
    
    def __init__(
        self,
        github_token: str,
        anthropic_api_key: str,
        synthesis_api_key: str,
        interval_hours: int = 6,
        max_results: int = 10,
        issue_threshold: int = 1
    ):
        """
        Initialize the AuditAgent.
        
        Args:
            github_token: GitHub personal access token
            anthropic_api_key: Anthropic API key for Claude
            synthesis_api_key: Synthesis API key for ERC-8004 receipts
            interval_hours: Hours between audit cycles
            max_results: Max repos to audit per cycle
            issue_threshold: Critical+High findings to file issue
        """
        self.github_token = github_token
        self.anthropic_api_key = anthropic_api_key
        self.synthesis_api_key = synthesis_api_key
        self.interval_hours = interval_hours
        self.max_results = max_results
        self.issue_threshold = issue_threshold
        
        # Set environment variables for submodules
        os.environ["GITHUB_TOKEN"] = github_token
        os.environ["ANTHROPIC_API_KEY"] = anthropic_api_key
        os.environ["SYNTHESIS_API_KEY"] = synthesis_api_key
        
        logger.info(f"AuditAgent initialized. Running every {interval_hours} hours.")
    
    def run_audit_cycle(self) -> Dict:
        """
        Run a single audit cycle: Discover → Scan → Interpret → Report → Receipt.
        
        Returns:
            Dict with cycle results
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
        
        logger.info("=" * 50)
        logger.info("Starting new audit cycle")
        logger.info("=" * 50)
        
        try:
            # Step 1: Discover new Solidity repositories
            logger.info("[1/5] Discovering Solidity repositories...")
            repos = discover_solidity_repos(
                self.github_token,
                max_results=self.max_results
            )
            
            if not repos:
                logger.info("No new repositories discovered")
                results["repos_discovered"] = 0
                return results
            
            # Rank by stars/forks
            ranked_repos = rank_repos(repos)
            results["repos_discovered"] = len(ranked_repos)
            logger.info(f"Discovered {len(ranked_repos)} repositories")
            
            # Process each repository
            for repo in ranked_repos:
                try:
                    logger.info(f"\n--- Auditing {repo['name']} ---")
                    
                    # Step 2: Scan repository with Slither
                    logger.info(f"[2/5] Scanning {repo['name']} with Slither...")
                    scan_results = scan_repository(
                        repo['clone_url'],
                        branch=repo.get('default_branch', 'main')
                    )
                    
                    if not scan_results.get("success"):
                        logger.warning(f"Scan failed: {scan_results.get('error')}")
                        results["errors"].append({
                            "repo": repo['name'],
                            "error": scan_results.get("error")
                        })
                        continue
                    
                    if not scan_results.get("results"):
                        logger.info(f"No findings in {repo['name']}")
                        continue
                    
                    results["repos_scanned"] += 1
                    
                    # Step 3: Interpret results with Claude
                    logger.info(f"[3/5] Interpreting results with Claude...")
                    report = interpret_results(
                        scan_results,
                        repo['name']
                    )
                    
                    logger.info(f"Found {len(report.findings)} issues "
                                f"(Critical: {report.critical_count}, "
                                f"High: {report.high_count})")
                    
                    if report.has_critical_or_high:
                        results["repos_with_findings"] += 1
                        
                        # Step 4: File GitHub issue if threshold met
                        logger.info(f"[4/5] Checking issue threshold...")
                        issue_url = report_findings(
                            self.github_token,
                            repo['name'],
                            report,
                            threshold=self.issue_threshold
                        )
                        
                        if issue_url:
                            logger.info(f"Filed issue: {issue_url}")
                            results["issues_filed"] += 1
                        else:
                            logger.info("Issue threshold not met, skipping")
                        
                        # Step 5: Mint on-chain receipt
                        logger.info(f"[5/5] Minting on-chain receipt...")
                        receipt = record_receipt(
                            audit_hash=report.audit_hash,
                            repo_name=report.repo_name,
                            timestamp=report.timestamp,
                            severity_summary=report.severity_breakdown,
                            github_issue_url=issue_url
                        )
                        
                        if receipt.get("success"):
                            logger.info(f"Receipt minted: {receipt.get('transaction_hash')}")
                            results["receipts_minted"] += 1
                        else:
                            logger.warning(f"Receipt failed: {receipt.get('error')}")
                            results["errors"].append({
                                "repo": repo['name'],
                                "stage": "receipt",
                                "error": receipt.get("error")
                            })
                    
                except Exception as e:
                    logger.error(f"Error auditing {repo['name']}: {e}")
                    results["errors"].append({
                        "repo": repo['name'],
                        "error": str(e)
                    })
                    continue
            
        except Exception as e:
            logger.error(f"Critical error in audit cycle: {e}")
            results["errors"].append({"cycle_error": str(e)})
        
        cycle_end = datetime.now()
        results["cycle_end"] = cycle_end.isoformat()
        results["duration_seconds"] = (cycle_end - cycle_start).total_seconds()
        
        logger.info("=" * 50)
        logger.info(f"Audit cycle complete in {results['duration_seconds']:.1f}s")
        logger.info(f"Scanned: {results['repos_scanned']}, "
                    f"Issues: {results['issues_filed']}, "
                    f"Receipts: {results['receipts_minted']}")
        logger.info("=" * 50)
        
        return results
    
    def run_continuously(self):
        """Run audit cycles on a schedule."""
        # Run immediately on start
        self.run_audit_cycle()
        
        # Schedule subsequent runs
        schedule.every(self.interval_hours).hours.do(self.run_audit_cycle)
        
        logger.info(f"Next audit in {self.interval_hours} hours")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def run_once(self):
        """Run a single audit cycle (no scheduling)."""
        return self.run_audit_cycle()


def start_api_server():
    """Start the FastAPI server."""
    import uvicorn
    from api.server import app
    
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)


def main():
    """Main entry point."""
    # Load environment variables
    github_token = os.environ.get("GITHUB_TOKEN")
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    synthesis_api_key = os.environ.get("SYNTHESIS_API_KEY")
    
    # Start API server if RUN_API=true (Railway)
    if os.environ.get("RUN_API", "false").lower() == "true":
        from threading import Thread
        api_thread = Thread(target=start_api_server, daemon=True)
        api_thread.start()
        logging.info("FastAPI server started on port {}".format(os.environ.get("PORT", 8000)))
    
    # Check required variables
    missing = []
    if not github_token:
        missing.append("GITHUB_TOKEN")
    if not anthropic_api_key:
        missing.append("ANTHROPIC_API_KEY")
    if not synthesis_api_key:
        missing.append("SYNTHESIS_API_KEY")
    
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        logger.info("Please set these before running:")
        logger.info("  export GITHUB_TOKEN=your_github_token")
        logger.info("  export ANTHROPIC_API_KEY=your_anthropic_key")
        logger.info("  export SYNTHESIS_API_KEY=your_synthesis_key")
        sys.exit(1)
    
    # Get configuration
    interval_hours = int(os.environ.get("AUDIT_INTERVAL_HOURS", "6"))
    max_results = int(os.environ.get("AUDIT_MAX_RESULTS", "10"))
    issue_threshold = int(os.environ.get("AUDIT_ISSUE_THRESHOLD", "1"))
    
    # Create and run agent
    agent = AuditAgent(
        github_token=github_token,
        anthropic_api_key=anthropic_api_key,
        synthesis_api_key=synthesis_api_key,
        interval_hours=interval_hours,
        max_results=max_results,
        issue_threshold=issue_threshold
    )
    
    # Check if running as daemon or one-shot
    if os.environ.get("AUDIT_DAEMON", "true").lower() == "true":
        agent.run_continuously()
    else:
        results = agent.run_once()
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
