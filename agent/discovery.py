"""
Discovery module for AuditAgent.
Queries GitHub API for recent Solidity repositories.
"""
import os
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from github import Github

logger = logging.getLogger(__name__)

SEEN_REPOS_FILE = "agent/seen_repos.json"


def load_seen_repos() -> set:
    """Load previously seen repository IDs from file."""
    if os.path.exists(SEEN_REPOS_FILE):
        with open(SEEN_REPOS_FILE, "r") as f:
            data = json.load(f)
            return set(data.get("seen_ids", []))
    return set()


def save_seen_repos(seen_ids: set) -> None:
    """Save seen repository IDs to file."""
    with open(SEEN_REPOS_FILE, "w") as f:
        json.dump({"seen_ids": list(seen_ids)}, f)


def discover_solidity_repos(
    token: str,
    max_results: int = 20,
    days_old: int = 30
) -> List[Dict]:
    """
    Query GitHub API for recent Solidity repositories.
    
    Args:
        token: GitHub personal access token
        max_results: Maximum number of repos to return
        days_old: Only include repos pushed within this many days
        
    Returns:
        List of dicts with repo info (id, name, url, stars, description)
    """
    g = Github(token)
    
    # Calculate date filter
    date_filter = (datetime.now() - timedelta(days=days_old)).strftime("%Y-%m-%d")
    
    # Search for Solidity repos pushed in the last N days
    query = f"language:solidity pushed:>={date_filter}"
    
    logger.info(f"Searching for Solidity repos with query: {query}")
    
    repos = []
    seen_ids = load_seen_repos()
    
    try:
        results = g.search_repositories(query=query, sort="pushed", order="desc")
        
        for repo in results:
            # Skip if we've already seen this repo
            if repo.id in seen_ids:
                continue
                
            repo_info = {
                "id": repo.id,
                "name": repo.full_name,
                "url": repo.html_url,
                "clone_url": repo.clone_url,
                "description": repo.description or "",
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "pushed_at": repo.pushed_at.isoformat() if repo.pushed_at else None,
                "default_branch": repo.default_branch,
                "owner": repo.owner.login,
            }
            repos.append(repo_info)
            seen_ids.add(repo.id)
            
            if len(repos) >= max_results:
                break
                
    except Exception as e:
        logger.error(f"GitHub API error during discovery: {e}")
        raise
    
    # Save updated seen repos
    save_seen_repos(seen_ids)
    
    logger.info(f"Discovered {len(repos)} new Solidity repos")
    return repos


def rank_repos(repos: List[Dict], stars_weight: float = 0.7, forks_weight: float = 0.3) -> List[Dict]:
    """
    Rank repositories by a weighted score of stars and forks.
    
    Args:
        repos: List of repo dicts
        stars_weight: Weight for star count
        forks_weight: Weight for fork count
        
    Returns:
        Sorted list of repos by score
    """
    for repo in repos:
        # Normalize and compute score
        stars = repo.get("stars", 0) or 0
        forks = repo.get("forks", 0) or 0
        repo["score"] = (stars * stars_weight) + (forks * forks_weight)
    
    return sorted(repos, key=lambda x: x["score"], reverse=True)


if __name__ == "__main__":
    # Test discovery
    logging.basicConfig(level=logging.INFO)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        repos = discover_solidity_repos(token)
        ranked = rank_repos(repos)
        for r in ranked[:5]:
            print(f"{r['name']} - {r['stars']} stars - {r['url']}")
    else:
        print("GITHUB_TOKEN not set")
