# AuditAgent 🤖

Autonomous smart contract security scanner that hunts for unaudited Solidity repos, scans them with Slither, interprets findings via Claude, files GitHub Issues, and mints on-chain ERC-8004 receipts.

## Features

- **Auto-Discovery**: Finds unaudited Solidity repositories on GitHub
- **Slither Scanning**: Static analysis from Trail of Bits
- **AI Interpretation**: Claude (Anthropic) generates human-readable reports
- **Issue Filing**: Automatically files security issues on GitHub
- **On-Chain Receipts**: ERC-8004 tokens on Base via Synthesis API
- **Dashboard**: Real-time stats and audit history

## Architecture

```
audit-agent/
├── agent/           # Autonomous agent modules
│   ├── discovery.py    # GitHub API search
│   ├── scanner.py      # Slither integration
│   ├── interpreter.py  # Claude analysis
│   ├── reporter.py     # GitHub Issues
│   ├── receipt.py      # ERC-8004 minting
│   └── main.py         # Orchestrator
├── api/             # FastAPI backend
│   ├── server.py       # REST API
│   ├── models.py       # Pydantic models
│   └── storage.py      # JSON persistence
├── frontend/        # Dashboard
│   └── index.html      # Single-page UI
└── audits/          # Audit records (JSON)
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude |
| `SYNTHESIS_API_KEY` | Yes | Synthesis API key for ERC-8004 |
| `PORT` | No | Server port (default: 8000) |
| `RUN_API` | No | Set `true` to start API server |
| `AUDIT_INTERVAL_HOURS` | No | Hours between audits (default: 6) |
| `AUDIT_MAX_RESULTS` | No | Max repos per cycle (default: 10) |
| `AUDIT_ISSUE_THRESHOLD` | No | Critical+High to file issue (default: 1) |
| `AUDIT_DAEMON` | No | Run continuously (default: true) |

## Setup

```bash
# Clone and install
git clone https://github.com/Pelz01/audit-agent.git
cd audit-agent
pip install -r requirements.txt

# Set environment variables
export GITHUB_TOKEN=ghp_xxx
export ANTHROPIC_API_KEY=sk-ant-xxx
export SYNTHESIS_API_KEY=sk-synth-xxx

# Run agent only
python -m agent.main

# Run API server only
python -m api.server

# Run both (Railway)
export RUN_API=true
python -m agent.main
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Frontend dashboard |
| `GET /audits` | Paginated audit list |
| `GET /audits/{id}` | Single audit details |
| `GET /stats` | Aggregate statistics |
| `GET /health` | Agent health status |

## Demo Script (2 min)

1. **Show Dashboard** — Visit deployed URL, show audit history
2. **Trigger Live Audit** — Run `python -m agent.main` on a test repo
3. **Show Slither Running** — Terminal output with findings
4. **Show Claude Report** — Generated security analysis
5. **Show GitHub Issue** — Link to filed issue
6. **Show On-Chain Receipt** — BaseScan transaction link

## Deployment (Railway)

1. Connect GitHub repo to Railway
2. Set environment variables in Railway dashboard
3. Deploy — Procfile starts uvicorn server
4. Visit `https://your-app.railway.app`

## Safety Guardrails

- Only public repositories
- Active repos only (commits within 90 days)
- Rate limited: max 10 audits/day
- Clear agent identification in issues
- No wallet/financial interactions
- Read-only except issue filing

## Tech Stack

- **Agent**: Python 3.11+
- **Scanner**: Slither (Trail of Bits)
- **AI**: Claude (Anthropic)
- **On-Chain**: ERC-8004 / Synthesis API (Base)
- **Backend**: FastAPI + Uvicorn
- **Storage**: JSON files (no DB)
- **Frontend**: Plain HTML/CSS/JS
- **Deployment**: Railway

## License

MIT
