# CITADEL

CITADEL is a local-first blue-team security assessment toolkit for Linux and Docker environments.

It helps identify risky configurations, collect evidence, and generate remediation-oriented reports.

## Planned Features

- Linux hardening checks
- Docker security audit
- Web exposure checks
- Secret and dependency scanning
- Incident timeline from logs
- Risk scoring
- HTML / JSON / PDF reports
- Vulnerable lab for before/after hardening demos

## AI-assisted risk advisory

CITADEL works fully offline by default. The offline advisor uses deterministic rule-based analysis to summarize scan results, prioritize remediation, and explain defensive next steps without sending data to any external service.

Optional AI-assisted advisory modes are planned for the OpenAI API and local Ollama deployments. These modes are intended for summarization, prioritization, and remediation explanation only, not exploitation or offensive guidance.
