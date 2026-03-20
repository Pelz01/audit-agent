"""
FastAPI server for AuditAgent v2.
Provides REST API for audits, stats, health checks, on-demand audits, and WebSocket terminal.
"""
import os
import json
import logging
import time
import asyncio
import requests
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List
from collections import deque
from datetime import datetime

from fastapi import FastAPI, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    AuditRecord,
    AuditListResponse,
    AgentStats,
    HealthResponse,
    SeverityBreakdown
)
from . import storage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

APP_START_TIME = time.time()

# Log buffer for WebSocket
log_buffer: deque = deque(maxlen=200)
active_connections: List[WebSocket] = []

# In-memory audit queue
audit_queue: asyncio.Queue = asyncio.Queue()
recent_audits: dict = {}  # repo_name -> timestamp


async def broadcast_log(message: str):
    """Broadcast a log line to all connected WebSocket clients."""
    timestamped = f"[{datetime.utcnow().strftime('%H:%M:%S')}] {message}"
    log_buffer.append(timestamped)
    
    for ws in active_connections[:]:
        try:
            await ws.send_text(timestamped)
        except:
            if ws in active_connections:
                active_connections.remove(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    logger.info("AuditAgent API starting up...")
    storage.STORAGE_DIR.mkdir(exist_ok=True)
    
    # Start background worker for audit queue
    asyncio.create_task(audit_worker())
    
    # Start the agent scheduler on startup (if RUN_AGENT=true)
    if os.environ.get("RUN_AGENT", "false").lower() == "true":
        import threading
        from agent.main import AuditAgent
        
        github_token = os.environ.get("GITHUB_TOKEN")
        anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
        synthesis_api_key = os.environ.get("SYNTHESIS_API_KEY")
        
        if github_token and anthropic_api_key and synthesis_api_key:
            agent = AuditAgent(
                github_token=github_token,
                anthropic_api_key=anthropic_api_key,
                synthesis_api_key=synthesis_api_key,
                interval_hours=int(os.environ.get("AUDIT_INTERVAL_HOURS", "6")),
                max_results=int(os.environ.get("AUDIT_MAX_RESULTS", "10")),
                issue_threshold=int(os.environ.get("AUDIT_ISSUE_THRESHOLD", "1"))
            )
            
            # Start agent in background thread
            thread = threading.Thread(target=agent.run_continuously, daemon=True)
            thread.start()
            logger.info("AuditAgent scheduler started")
        else:
            logger.warning("Missing env vars - agent not started")
    
    yield
    
    logger.info("AuditAgent API shutting down...")


async def audit_worker():
    """Background worker that processes the audit queue."""
    from agent.main import AuditAgent
    
    github_token = os.environ.get("GITHUB_TOKEN")
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    synthesis_api_key = os.environ.get("SYNTHESIS_API_KEY")
    
    if not all([github_token, anthropic_api_key, synthesis_api_key]):
        logger.warning("Audit worker not started - missing environment variables")
        return
    
    agent = AuditAgent(
        github_token=github_token,
        anthropic_api_key=anthropic_api_key,
        synthesis_api_key=synthesis_api_key,
        interval_hours=6,
        max_results=10
    )
    
    while True:
        try:
            repo = await audit_queue.get()
            await broadcast_log(f"[QUEUED] Starting audit for {repo}")
            agent.run_once(repo_override=repo)
            await audit_queue.task_done()
        except Exception as e:
            await broadcast_log(f"[ERROR] Audit worker error: {e}")
            await asyncio.sleep(1)


app = FastAPI(
    title="AuditAgent API",
    description="REST API for AuditAgent - autonomous smart contract security scanner",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Serve the frontend dashboard."""
    frontend_path = Path(__file__).parent.parent / "frontend" / "index.html"
    if frontend_path.exists():
        return FileResponse(frontend_path)
    return HTMLResponse(content="<h1>AuditAgent API</h1><p>Frontend not found</p>")


@app.get("/audits", response_model=AuditListResponse)
async def get_audits(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100)
):
    """Get paginated list of all audits."""
    result = storage.list_audits(page=page, page_size=page_size)
    return AuditListResponse(**result)


@app.get("/audits/{audit_id}", response_model=AuditRecord)
async def get_audit(audit_id: str):
    """Get a specific audit by ID."""
    audit = storage.get_audit(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.get("/stats", response_model=AgentStats)
async def get_stats():
    """Get aggregate statistics."""
    return storage.get_stats()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    last_run = storage.get_last_audit_time()
    audits_today = storage.get_audits_today()
    
    return HealthResponse(
        status="healthy",
        agent_running=True,
        last_run=last_run,
        audits_today=audits_today,
        uptime_seconds=time.time() - APP_START_TIME
    )


@app.post("/audit")
async def submit_audit(request: dict):
    """
    Submit a repository for on-demand auditing.
    
    Body: { "repository": "owner/repo-name" }
    """
    repository = request.get("repository", "").strip()
    
    # Validate format - accept both owner/repo and full GitHub URL
    if not repository:
        raise HTTPException(status_code=400, detail="Repository is required")
    
    # Strip GitHub URL if provided
    if "github.com" in repository:
        # Extract owner/repo from URL
        parts = repository.rstrip("/").split("/")
        if len(parts) >= 2:
            repository = f"{parts[-2]}/{parts[-1]}"
    
    # Validate format
    if "/" not in repository:
        raise HTTPException(status_code=400, detail="Repository must be in owner/repo format")
    
    # Check if repo exists on GitHub
    owner, repo = repository.split("/")
    try:
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10
        )
        if response.status_code == 404:
            raise HTTPException(status_code=400, detail="Repository not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to validate repository: {str(e)}")
    
    # Check for Solidity files
    try:
        response = requests.get(
            f"https://api.github.com/search/code?q=extension:sol+repo:{owner}/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) == 0:
                raise HTTPException(status_code=400, detail="No Solidity files found in this repository")
    except HTTPException:
        raise
    except Exception:
        pass  # Skip this check if it fails
    
    # Check recent audits (10 minute cooldown)
    now = time.time()
    if repository in recent_audits:
        if now - recent_audits[repository] < 600:  # 10 minutes
            raise HTTPException(status_code=429, detail="This repository was recently audited. Please wait before re-submitting")
    
    # Add to queue
    recent_audits[repository] = now
    await audit_queue.put(repository)
    
    return {
        "status": "queued",
        "repository": repository,
        "message": "Audit started. Watch the terminal for live progress.",
        "estimated_duration": "2-4 minutes"
    }


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for live terminal output."""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        # Send last 50 log lines to new connections
        recent_logs = list(log_buffer)[-50:]
        for log in recent_logs:
            await websocket.send_text(log)
        
        # Keep connection open
        while True:
            try:
                # Wait for any message (ping/pong keepalive)
                await websocket.receive_text()
            except:
                break
    except:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.get("/favicon.ico")
async def favicon():
    """Serve favicon."""
    return None


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "api.server:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )
