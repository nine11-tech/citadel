# CITADEL

**CITADEL** is an AI-assisted local-first blue-team security assessment toolkit for Linux and Docker environments.

It helps developers, students, sysadmins, and security analysts identify risky configurations, collect evidence, calculate risk scores, and generate remediation-oriented reports.

The project focuses on defensive cybersecurity: infrastructure hardening, container security, evidence-based reporting, and incident readiness.

---

## Why CITADEL?

Modern environments often rely on containers, local development stacks, CI/CD pipelines, and exposed services. Misconfigurations such as privileged containers, Docker socket exposure, host networking, secrets in environment variables, and unpinned images can seriously weaken security.

CITADEL provides a simple way to detect these risks and produce clear reports that can be used for review, remediation, and audit evidence.

---

## Current Features

### Docker Security Scanner

CITADEL currently detects risky Docker Compose configurations such as:

- Privileged containers
- Docker socket mounted inside containers
- Host network mode
- Images using `latest` or missing explicit tags
- Containers running as root
- Dangerous Linux capabilities
- Sensitive environment variables
- Sensitive service ports exposed
- Missing healthchecks

### Risk Scoring

Each finding is assigned a severity:

- Critical
- High
- Medium
- Low
- Info

CITADEL calculates a global security score from `0` to `100` based on the detected issues.

### Report Generation

CITADEL can export scan results as structured JSON reports.

### AI-assisted Risk Advisory

CITADEL includes an advisory layer for explaining and prioritizing findings.

Current mode:

- **Offline mode**: deterministic rule-based advisory generation, no API key required.

Planned modes:

- **Ollama mode**: local LLM-based advisory support.
- **OpenAI mode**: API-based advisory support.

The AI-assisted layer is designed for:

- Executive summaries
- Remediation prioritization
- Human-readable risk explanations
- Defensive next-step recommendations

It is not designed for exploitation or offensive automation.

---

## Quick Demo

Scan the intentionally vulnerable Docker lab:

```bash
citadel scan examples/vulnerable-docker --json-output reports/docker-demo.json

Generate an offline advisory:

```bash
citadel advisor reports/docker-demo.json --mode offline --output reports/advisory.md
```

Example output:

```text
Final score: 0
Critical: 2
High: 5
Medium: 4
Low: 1
```

---

## Example Finding Categories

| Category                     | Example                                   |
| ---------------------------- | ----------------------------------------- |
| Container isolation          | Privileged container enabled              |
| Host exposure                | Docker socket mounted                     |
| Network security             | Host network mode enabled                 |
| Secret management            | Sensitive environment variable configured |
| Runtime hardening            | Container runs as root                    |
| Service exposure             | Sensitive port exposed                    |
| Reliability/security hygiene | Missing healthcheck                       |

---

## Project Structure

```text
citadel/
├── citadel/
│   ├── advisor.py
│   ├── cli.py
│   ├── models.py
│   ├── scoring.py
│   └── scanners/
│       └── docker.py
├── examples/
│   └── vulnerable-docker/
├── reports/
├── tests/
└── README.md
```

---

## Installation

```bash
git clone https://github.com/nine11-tech/citadel.git
cd citadel

python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

---

## Usage examples

Show version:

```bash
citadel version
```

Run a scan:

```bash
citadel scan examples/vulnerable-docker --json-output reports/docker-demo.json
```

Generate advisory:

```bash
citadel advisor reports/docker-demo.json --mode offline --output reports/advisory.md
```

Run tests:

```bash
pytest
```

---

## Security Philosophy

CITADEL is built around defensive cybersecurity principles:

* Read-only scanning
* No exploitation
* No destructive actions
* Evidence-based findings
* Clear remediation guidance
* Local-first operation
* AI assistance only for summarization and prioritization and open to gradually developing agentic tasks 

---

## Roadmap

Planned modules:

* Linux hardening scanner
* Web exposure and security headers scanner
* Log-based incident timeline
* HTML/PDF report generation
* local Ollama advisory mode
* OpenAI advisory mode
* GitHub Actions CI pipeline

---

## Status

CITADEL is under active development.

The current version includes the core data model, risk scoring, Docker Compose security scanning, JSON report export, and offline AI-assisted risk advisory generation.

````

Then run:

```bash
pytest
git status
````
