"""
Scanner module for AuditAgent.
Clones repositories and runs Slither static analysis.
"""
import os
import json
import logging
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def clone_repo(repo_url: str, branch: str = "main") -> str:
    """
    Clone a GitHub repository to a temporary directory.
    
    Args:
        repo_url: HTTPS clone URL of the repository
        branch: Branch to clone (default: main)
        
    Returns:
        Path to the cloned repository
    """
    temp_dir = tempfile.mkdtemp(prefix="audit_agent_")
    
    logger.info(f"Cloning {repo_url} to {temp_dir}")
    
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            # Try without branch specified (might be master or other)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, temp_dir],
                capture_output=True,
                text=True,
                timeout=120
            )
            
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr}")
            
        return temp_dir
        
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError("Git clone timed out")


def find_solidity_files(repo_path: str) -> List[str]:
    """
    Find all Solidity (.sol) files in a directory.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        List of absolute paths to .sol files
    """
    sol_files = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".sol"):
                sol_files.append(os.path.join(root, file))
    
    logger.info(f"Found {len(sol_files)} Solidity files")
    return sol_files


def run_slither(repo_path: str, sol_files: List[str]) -> Dict:
    """
    Run Slither analysis on Solidity files.
    
    Args:
        repo_path: Path to the repository
        sol_files: List of .sol file paths
        
    Returns:
        Slither JSON output as dict
    """
    if not sol_files:
        logger.warning("No Solidity files to scan")
        return {"success": False, "error": "No Solidity files found", "results": []}
    
    # Create a temporary output file
    output_file = tempfile.mktemp(suffix=".json")
    
    try:
        # Run Slither with JSON output
        cmd = ["slither", ".", "--json", output_file, "--disable-color"]
        
        logger.info(f"Running Slither on {len(sol_files)} files")
        
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        # Read the JSON output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                slither_output = json.load(f)
            
            # Ensure it's in list format
            if isinstance(slither_output, dict):
                if "results" in slither_output:
                    slither_output = slither_output["results"]
                slither_output = [slither_output] if slither_output else []
            
            os.remove(output_file)
            
            return {
                "success": True,
                "results": slither_output,
                "files_scanned": len(sol_files),
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        else:
            # Slither might have run but no output file
            return {
                "success": False,
                "error": "Slither did not produce output",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "results": []
            }
            
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Slither not installed. Run: pip install slither-analyzer",
            "results": []
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Slither analysis timed out after 5 minutes",
            "results": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "results": []
        }


def scan_repository(repo_url: str, branch: str = "main", keep_repo: bool = False) -> Dict:
    """
    Full scan pipeline: clone repo, find .sol files, run Slither.
    
    Args:
        repo_url: HTTPS URL of the repository
        branch: Branch to checkout
        keep_repo: If True, don't delete the repo after scanning (for secret scanning)
        
    Returns:
        Dict with scan results and metadata
    """
    repo_path = None
    
    try:
        # Clone the repository
        repo_path = clone_repo(repo_url, branch)
        
        # Find Solidity files
        sol_files = find_solidity_files(repo_path)
        
        if not sol_files:
            return {
                "success": False,
                "error": "No Solidity files found in repository",
                "repo_url": repo_url,
                "files_scanned": 0,
                "results": [],
                "secrets": [],
                "has_secrets": False
            }
        
        # Run Slither
        slither_results = run_slither(repo_path, sol_files)
        
        # Run Secret Scanner
        secret_findings = []
        secret_severity = None
        try:
            from agent.secret_scanner import scan_secrets
            secret_findings = scan_secrets(repo_path)
            if secret_findings:
                # Determine max severity
                severities = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1}
                max_sev = max(secret_findings, key=lambda x: severities.get(x['severity'], 0))
                secret_severity = max_sev['severity']
        except Exception as e:
            logger.warning(f"Secret scan failed: {e}")
        
        return {
            "success": slither_results.get("success", False),
            "repo_url": repo_url,
            "repo_path": repo_path,
            "files_scanned": slither_results.get("files_scanned", 0),
            "results": slither_results.get("results", []),
            "error": slither_results.get("error"),
            "slither_stdout": slither_results.get("stdout"),
            "slither_stderr": slither_results.get("stderr"),
            "secrets": secret_findings,
            "has_secrets": len(secret_findings) > 0,
            "secret_severity": secret_severity
        }
        
    except Exception as e:
        logger.error(f"Scan failed for {repo_url}: {e}")
        return {
            "success": False,
            "error": str(e),
            "repo_url": repo_url,
            "files_scanned": 0,
            "results": [],
            "secrets": [],
            "has_secrets": False
        }
    finally:
        # Cleanup cloned repo (unless keep_repo is True)
        if repo_path and os.path.exists(repo_path) and not keep_repo:
            try:
                shutil.rmtree(repo_path)
                logger.info(f"Cleaned up {repo_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {repo_path}: {e}")


if __name__ == "__main__":
    # Test scanning
    logging.basicConfig(level=logging.INFO)
    # This would require a real repo URL
    print("Scanner module loaded. Use scan_repository() to scan a repo.")
