"""
Secret Scanner Module for AuditAgent.
Scans repositories for accidentally exposed secrets.
"""
import os
import re
from pathlib import Path
from typing import List, Dict

# Common BIP-39 words for seed phrase detection
BIP39_COMMON_WORDS = {
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice', 'aerobic', 'afford', 'afraid', 'again', 'age', 'agent', 'agree',
    'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
    'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also',
    'alter', 'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst',
    'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal', 'ankle', 'announce',
    'annual', 'another', 'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart',
    'apology', 'appear', 'apple', 'approve', 'april', 'arch', 'arctic', 'area', 'arena',
    'argue', 'arm', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow',
    'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist',
    'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract',
    'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average',
    'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis',
    'baby', 'balance', 'bamboo', 'banana'
}

# Compiled regex patterns
ETH_PRIVATE_KEY_PATTERN = re.compile(r'0x[a-fA-F0-9]{64}')
AWS_ACCESS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')
AWS_SECRET_KEY_PATTERN = re.compile(r'[a-zA-Z0-9/+=]{40}')
INFURA_KEY_PATTERN = re.compile(r'[a-f0-9]{32}')
ALCHEMY_KEY_PATTERN = re.compile(r'[a-zA-Z0-9_-]{32,}')
QUICKNODE_KEY_PATTERN = re.compile(r'[a-zA-Z0-9]{32,}')
GENERIC_API_KEY_PATTERN = re.compile(
    r'(api_key|apikey|api-key|secret|token|password|passwd|credential)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    re.IGNORECASE
)
PRIVATE_KEY_FILE_PATTERN = re.compile(
    r'BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY',
    re.IGNORECASE
)

# Placeholder values to exclude
PLACEHOLDERS = {
    'your_key_here', 'xxx', 'placeholder', 'changeme', 'example', 
    'todo', 'fixme', 'insert_here', 'your_key', 'your_secret',
    '1234567890', 'abcdefghij', 'replace_this'
}

# Skip patterns in filenames
SKIP_PATTERNS = ['test', 'mock', 'example', 'sample', 'fixture']


def should_skip_file(file_path: Path) -> bool:
    """Check if file should be skipped (test files, binaries, etc)."""
    name = file_path.name.lower()
    
    # Skip test/mock/example files
    for pattern in SKIP_PATTERNS:
        if pattern in name:
            return True
    
    # Skip binary files
    try:
        with open(file_path, 'rb') as f:
            f.seek(0)
            chunk = f.read(1024)
            if b'\x00' in chunk:  # null bytes = binary
                return True
    except:
        return True
    
    # Skip files > 1MB
    if file_path.stat().st_size > 1024 * 1024:
        return True
    
    return False


def should_skip_dir(dir_path: Path) -> bool:
    """Check if directory should be skipped entirely."""
    name = dir_path.name.lower()
    skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'out', 'target', '__pycache__', '.venv', 'venv'}
    return name in skip_dirs


def redact_evidence(value: str, pattern_type: str = 'default') -> str:
    """Redact secret evidence - show first 6 and last 4 chars."""
    if len(value) <= 12:
        return '*' * len(value)
    
    if pattern_type == 'eth_key':
        return f"0x{value[4:10]}**...{value[-4:]}"
    else:
        return f"{value[:4]}**...{value[-4:]}"


def check_line_for_placeholder(line: str) -> bool:
    """Check if a line contains placeholder text."""
    line_lower = line.lower()
    for placeholder in PLACEHOLDERS:
        if placeholder in line_lower:
            return True
    return False


def check_line_for_example(line: str) -> bool:
    """Check if line mentions example/test/placeholder (false positive check)."""
    line_lower = line.lower()
    false_positive_words = ['example', 'test', 'placeholder', 'dummy', 'fake', 'mock', 'sample']
    return any(word in line_lower for word in false_positive_words)


def detect_ethereum_keys(content: str, file_path: str) -> List[Dict]:
    """Detect Ethereum private keys."""
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Skip test/example lines
        if check_line_for_example(line):
            continue
            
        matches = ETH_PRIVATE_KEY_PATTERN.findall(line)
        for match in matches:
            if not check_line_for_placeholder(line):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "Ethereum Private Key Exposed",
                    "file": file_path,
                    "line": i,
                    "description": "A 64-character hex string prefixed with 0x was found. This matches the format of an Ethereum private key. If this is a real key, any funds in the associated wallet are at immediate risk.",
                    "evidence": redact_evidence(match, 'eth_key'),
                    "recommendation": "Immediately rotate this key. Remove from git history using git filter-repo or BFG Repo Cleaner. Add .env to .gitignore."
                })
                break  # Only one per line
    
    return findings


def detect_seed_phrases(content: str, file_path: str) -> List[Dict]:
    """Detect BIP-39 mnemonic seed phrases."""
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Skip test/example lines
        if check_line_for_example(line):
            continue
            
        words = line.split()
        if len(words) < 12:
            continue
            
        # Check for 12+ consecutive BIP-39 common words
        consecutive_count = 0
        potential_phrase = []
        
        for word in words:
            word_clean = word.strip(',."\'')
            if word_clean.lower() in BIP39_COMMON_WORDS:
                consecutive_count += 1
                potential_phrase.append(word_clean)
            else:
                if consecutive_count >= 12:
                    # Found a seed phrase!
                    phrase_preview = ' '.join(potential_phrase[:4]) + ' ... ' + ' '.join(potential_phrase[-4:])
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "Wallet Seed Phrase Exposed",
                        "file": file_path,
                        "line": i,
                        "description": f"A sequence of {consecutive_count} words matching the BIP-39 mnemonic format was found. If this is a real seed phrase, all wallets derived from it are at immediate risk.",
                        "evidence": phrase_preview,
                        "recommendation": "Immediately move all funds from derived wallets. This seed phrase should be considered compromised. Generate new wallets with fresh seed phrases."
                    })
                    break
                consecutive_count = 0
                potential_phrase = []
        
        if findings:  # Only check first potential match per file
            break
    
    return findings


def detect_env_files(repo_path: str, file_path: str) -> List[Dict]:
    """Detect committed .env files."""
    findings = []
    name = os.path.basename(file_path)
    
    if name.startswith('.env') and ('.' not in name or name.count('.') == 1):
        # It's a .env file
        try:
            with open(file_path, 'r') as f:
                lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]
            
            keys = []
            for line in lines[:5]:  # First 5 non-empty lines
                if '=' in line:
                    key = line.split('=')[0]
                    keys.append(key)
            
            findings.append({
                "severity": "CRITICAL",
                "title": "Environment File Committed to Repository",
                "file": file_path,
                "line": 0,
                "description": f"An environment configuration file ({name}) was found committed to the repository. These files typically contain API keys, private keys, and other secrets.",
                "evidence": f"Keys: {', '.join(keys)}",
                "recommendation": "Remove this file from git history. Add .env to .gitignore. Rotate all credentials that were in this file."
            })
        except Exception as e:
            pass
    
    return findings


def detect_rpc_keys(content: str, file_path: str) -> List[Dict]:
    """Detect Infura/Alchemy/QuickNode API keys."""
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines, 1):
        if check_line_for_example(line):
            continue
        
        # Check nearby lines (within 3 lines) for provider name
        context_start = max(0, i - 3)
        context_end = min(len(lines), i + 3)
        context = '\n'.join(lines[context_start:context_end]).lower()
        
        # Infura
        if 'infura' in context:
            matches = INFURA_KEY_PATTERN.findall(line)
            for match in matches:
                if not check_line_for_placeholder(line):
                    findings.append({
                        "severity": "HIGH",
                        "title": "Infura API Key Exposed",
                        "file": file_path,
                        "line": i,
                        "description": "An Infura API key was found. This key can be used to make API calls billed to the repository owner.",
                        "evidence": redact_evidence(match),
                        "recommendation": "Rotate this API key in the Infura dashboard. Add to .env and remove from code."
                    })
        
        # Alchemy
        if 'alchemy' in context:
            matches = ALCHEMY_KEY_PATTERN.findall(line)
            for match in matches:
                if not check_line_for_placeholder(line):
                    findings.append({
                        "severity": "HIGH",
                        "title": "Alchemy API Key Exposed",
                        "file": file_path,
                        "line": i,
                        "description": "An Alchemy API key was found. This key can be used to make API calls billed to the repository owner.",
                        "evidence": redact_evidence(match),
                        "recommendation": "Rotate this API key in the Alchemy dashboard. Add to .env and remove from code."
                    })
        
        # QuickNode
        if 'quicknode' in context:
            matches = QUICKNODE_KEY_PATTERN.findall(line)
            for match in matches:
                if not check_line_for_placeholder(line):
                    findings.append({
                        "severity": "HIGH",
                        "title": "QuickNode API Key Exposed",
                        "file": file_path,
                        "line": i,
                        "description": "A QuickNode API key was found. This key can be used to make API calls billed to the repository owner.",
                        "evidence": redact_evidence(match),
                        "recommendation": "Rotate this API key in the QuickNode dashboard. Add to .env and remove from code."
                    })
    
    return findings


def detect_generic_keys(content: str, file_path: str) -> List[Dict]:
    """Detect generic API keys and secrets."""
    findings = []
    lines = content.split('\n')
    
    # Limit to first 5 secrets per file
    found_count = 0
    
    for i, line in enumerate(lines, 1):
        if found_count >= 5:
            break
        if check_line_for_example(line):
            continue
            
        matches = GENERIC_API_KEY_PATTERN.findall(line)
        for match in matches:
            if not check_line_for_placeholder(line):
                # Extract the value part
                parts = line.split('=', 1)
                if len(parts) == 2:
                    value = parts[1].strip(' "\'')
                    if len(value) >= 20:
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "Potential API Key or Secret Exposed",
                            "file": file_path,
                            "line": i,
                            "description": "A variable assignment matching common secret naming patterns was found with a value of 20+ characters.",
                            "evidence": redact_evidence(value),
                            "recommendation": "Verify if this is a real secret. If so, rotate it and move to environment variables."
                        })
                        found_count += 1
                        break
    
    return findings


def detect_aws_keys(content: str, file_path: str) -> List[Dict]:
    """Detect AWS access keys."""
    findings = []
    lines = content.split('\n')
    
    # Check for access key ID
    for i, line in enumerate(lines, 1):
        if check_line_for_example(line):
            continue
            
        matches = AWS_ACCESS_KEY_PATTERN.findall(line)
        for match in matches:
            findings.append({
                "severity": "CRITICAL",
                "title": "AWS Access Key ID Exposed",
                "file": file_path,
                "line": i,
                "description": "An AWS Access Key ID was found. This provides access to AWS cloud infrastructure.",
                "evidence": f"AKIA{match[:4]}***{match[-4:]}",
                "recommendation": "Immediately rotate this key in AWS IAM. Delete and create a new one."
            })
            break
    
    # Check for secret key (nearby)
    if findings:
        for i, line in enumerate(lines, 1):
            if 'aws_secret' in line.lower() or 'secret_access' in line.lower():
                matches = AWS_SECRET_KEY_PATTERN.findall(line)
                for match in matches:
                    if not check_line_for_placeholder(line):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "AWS Secret Access Key Exposed",
                            "file": file_path,
                            "line": i,
                            "description": "An AWS Secret Access Key was found. Combined with the Access Key ID, this provides full AWS access.",
                            "evidence": redact_evidence(match),
                            "recommendation": "Immediately rotate this key pair in AWS IAM."
                        })
                        break
    
    return findings


def detect_private_key_files(content: str, file_path: str) -> List[Dict]:
    """Detect PEM-encoded private key files."""
    findings = []
    
    if PRIVATE_KEY_FILE_PATTERN.search(content):
        findings.append({
            "severity": "CRITICAL",
            "title": "Private Key File Committed",
            "file": file_path,
            "line": 0,
            "description": "A PEM-encoded private key was found committed to the repository. This provides direct access to secured systems.",
            "evidence": "[PEM file content]",
            "recommendation": "Immediately remove this file from the repository. Rotate any credentials associated with this key."
        })
    
    return findings


def scan_secrets(repo_path: str) -> List[Dict]:
    """
    Scan a repository for exposed secrets.
    
    Args:
        repo_path: Absolute path to the cloned repository
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    seen_secrets = set()  # For deduplication
    
    repo_path = Path(repo_path)
    
    # Walk the directory tree
    for root, dirs, files in os.walk(repo_path):
        # Skip certain directories
        dirs[:] = [d for d in dirs if not should_skip_dir(Path(root) / d)]
        
        root_path = Path(root)
        
        for filename in files:
            file_path = root_path / filename
            rel_path = str(file_path.relative_to(repo_path))
            
            # Check for .env files first (whole file check)
            env_findings = detect_env_files(repo_path, rel_path)
            for f in env_findings:
                findings.append(f)
            
            # Skip other checks for .env files
            if filename.startswith('.env'):
                continue
            
            # Skip binary/large files
            if should_skip_file(file_path):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                continue
            
            # Run all detectors
            detectors = [
                detect_ethereum_keys,
                detect_seed_phrases,
                detect_rpc_keys,
                detect_generic_keys,
                detect_aws_keys,
                detect_private_key_files,
            ]
            
            for detector in detectors:
                try:
                    matches = detector(content, rel_path)
                    for match in matches:
                        # Deduplicate by evidence
                        evidence = match.get('evidence', '')
                        if evidence not in seen_secrets:
                            seen_secrets.add(evidence)
                            findings.append(match)
                except Exception as e:
                    continue  # Skip failed detectors
    
    return findings


if __name__ == "__main__":
    # Test the scanner
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmp:
        # Test 1 - Private key
        with open(os.path.join(tmp, "config.js"), "w") as f:
            f.write('const PK = "0x4c0883a69102937d6231471b5dbb6e538eba2ef7e5a4dc6a0a8a5f3b2f4c9e1d"')
        
        # Test 2 - .env file
        with open(os.path.join(tmp, ".env"), "w") as f:
            f.write("PRIVATE_KEY=4c0883a69102937d6231471b5dbb6e538eba2ef7e5a4dc6a0a8a5f3b2f4c9e1d\n")
            f.write("INFURA_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\n")
        
        # Test 3 - Test file (should skip)
        with open(os.path.join(tmp, "test_example.js"), "w") as f:
            f.write('// example key: 0x4c0883a69102937d6231471b5dbb6e538eba2ef7e5a4dc6a0a8a5f3b2f4c9e1d')
        
        findings = scan_secrets(tmp)
        
        print(f"Found {len(findings)} findings:")
        for f in findings:
            print(f"  - {f['title']} ({f['severity']}) in {f['file']}")
