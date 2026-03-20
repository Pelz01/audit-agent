# AuditAgent

Autonomous smart contract security agent that discovers, scans, and audits Solidity repositories.

## Overview

AuditAgent is an automated security auditing system that:

1. **Discovers** recent Solidity repositories from GitHub
2. **Scans** them using Slither static analysis
3. **Interprets** results with Claude AI for detailed analysis
4. **Reports** critical findings via GitHub Issues
5. **Records** audit receipts on-chain via Synthesis ERC-8004

## Installation

```bash
# Clone the repository
git clone https://github.com/Pelz01/audit-agent.git
cd audit-agent

# Install dependencies
pip install -r requirements.txt

# Install Slither
pip install slither-analyzer
```

## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Required environment variables:
- `GITHUB_TOKEN` - GitHub personal access token
- `ANTHROPIC_API_KEY` - Anthropic API key for Claude
- `SYNTHESIS_API_KEY` - Synthesis API key for on-chain receipts

Optional variables:
- `AUDIT_INTERVAL_HOURS` - Hours between audit cycles (default: 6)
- `AUDIT_MAX_RESULTS` - Max repos to audit per cycle (default: 10)
- `AUDIT_ISSUE_THRESHOLD` - Critical+High findings to file issue (default: 1)
- `AUDIT_DAEMON` - Run continuously (default: true)

## Usage

### Run Once
```bash
AUDIT_DAEMON=false python -m agent.main
```

### Run as Daemon (default)
```bash
python -m agent.main
```

## Architecture

```
agent/
├── discovery.py   # Discover Solidity repos via GitHub API
├── scanner.py     # Clone & run Slither analysis
├── interpreter.py # Claude AI interpretation
├── reporter.py    # File GitHub Issues
├── receipt.py     # Mint on-chain receipts
└── main.py        # Orchestrator
```

## Output

Each audit cycle produces:
- GitHub Issue for critical/high findings (if threshold met)
- On-chain receipt via Synthesis ERC-8004
- Log file: `audit_agent.log`

## License

MIT
