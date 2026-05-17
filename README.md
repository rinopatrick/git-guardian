# Git Guardian

AI-powered supply chain security scanner for npm packages.

## Features

- Scan npm packages for malicious patterns
- Detect typosquatting attacks
- AI-powered code analysis using mimo-v2.5-pro
- Generate security reports

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a single package
git-guardian scan lodash

# Scan with deep analysis
git-guardian scan express --deep

# Scan package.json dependencies
git-guardian scan-lockfile package-lock.json
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
