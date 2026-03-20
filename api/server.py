"""
FastAPI server for AuditAgent.
Provides REST API for audits, stats, and health checks.
Also serves the frontend dashboard.
"""
import os
import logging
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
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

# App start time for uptime calculation
APP_START_TIME = time.time()

# Track if agent is running (would be connected to actual agent in production)
agent_process: Optional[object] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    logger.info("AuditAgent API starting up...")
    
    # Initialize storage directory
    storage.STORAGE_DIR.mkdir(exist_ok=True)
    logger.info(f"Storage directory: {storage.STORAGE_DIR}")
    
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


# Create FastAPI app
app = FastAPI(
    title="AuditAgent API",
    description="REST API for AuditAgent - autonomous smart contract security scanner",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
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
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page")
):
    """
    Get paginated list of all audits.
    
    Returns a list of audit records with pagination info.
    """
    result = storage.list_audits(page=page, page_size=page_size)
    return AuditListResponse(**result)


@app.get("/audits/{audit_id}", response_model=AuditRecord)
async def get_audit(audit_id: str):
    """
    Get a specific audit by ID.
    
    Returns the full audit record including Slither output and Claude report.
    """
    audit = storage.get_audit(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.get("/stats", response_model=AgentStats)
async def get_stats():
    """
    Get aggregate statistics.
    
    Returns total audits, vulnerabilities found, issues filed, and receipts minted.
    """
    return storage.get_stats()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns agent status and last run time.
    """
    last_run = storage.get_last_audit_time()
    audits_today = storage.get_audits_today()
    
    # Determine if agent is running (in production, check actual process)
    agent_running = True  # Would check actual agent process
    
    return HealthResponse(
        status="healthy" if agent_running else "degraded",
        agent_running=agent_running,
        last_run=last_run,
        audits_today=audits_today,
        uptime_seconds=time.time() - APP_START_TIME
    )


@app.get("/favicon.ico")
async def favicon():
    """Serve favicon (empty 204 response)."""
    return None


# Error handlers
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