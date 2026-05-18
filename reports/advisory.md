# CITADEL Risk Advisory

**Target:** examples/vulnerable-docker
**Global score:** 0/100

## Severity summary

- Critical: 2
- High: 5
- Medium: 4
- Low: 1
- Info: 0
- Total findings: 12

## Executive summary

CITADEL identified 12 finding(s), with the highest severity rated as critical. The current score is 0/100. Remediation should prioritize issues that reduce isolation, expose sensitive services, or place secrets and privileged access in runtime configuration.

## Top findings

1. **DOCKER-001: Privileged container enabled**
   - Severity: critical
   - Asset: vulnerable-app
   - Impact: Privileged containers can bypass normal container isolation controls.
   - Remediation: Remove privileged mode and grant only the specific permissions required.

2. **DOCKER-002: Docker socket mounted into container**
   - Severity: critical
   - Asset: vulnerable-app
   - Impact: Access to the Docker socket can allow control of the host Docker daemon.
   - Remediation: Avoid mounting the Docker socket into containers.

3. **DOCKER-003: Host network mode enabled**
   - Severity: high
   - Asset: vulnerable-app
   - Impact: Host networking reduces network isolation between the container and host.
   - Remediation: Use a dedicated Docker network instead of host networking.

4. **DOCKER-006: Dangerous Linux capability added**
   - Severity: high
   - Asset: vulnerable-app
   - Impact: Extra capabilities can weaken container isolation and expand attack impact.
   - Remediation: Remove unnecessary capabilities and use the least privilege set required.

5. **DOCKER-006: Dangerous Linux capability added**
   - Severity: high
   - Asset: vulnerable-app
   - Impact: Extra capabilities can weaken container isolation and expand attack impact.
   - Remediation: Remove unnecessary capabilities and use the least privilege set required.


## Remediation priority

1. Resolve critical findings first, especially issues that weaken container isolation or expose host control surfaces.
2. Address high findings second, focusing on reduced privileges, network exposure, and sensitive configuration handling.
3. Remediate medium findings third by pinning versions, reducing exposed services, and enforcing safer runtime defaults.

## Defensive next steps

- Validate each finding against the intended deployment architecture.
- Apply least privilege to container users, capabilities, mounts, and network settings.
- Move sensitive values out of Compose files and into an approved secret management flow.
- Re-run CITADEL after remediation to confirm score and finding count improvements.
- Preserve generated JSON and Markdown reports for audit evidence and change tracking.

## Limitations

Offline mode uses deterministic rule-based analysis. It does not call external AI services, does not infer business context beyond the scan report, and should be reviewed by a qualified cybersecurity specialist before operational decisions are finalized.
