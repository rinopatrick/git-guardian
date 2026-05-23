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

---

## Sponsor

If this project helps you, you can support ongoing development:

[![Saweria](https://img.shields.io/badge/Support-Saweria-FF5722?style=flat-square&logo=wallet)](https://saweria.co/rinopatrick)
[![Ko-fi](https://img.shields.io/badge/Support-Ko--fi-FF5E5B?style=flat-square&logo=kofi)](https://ko-fi.com/rinopatrick)
