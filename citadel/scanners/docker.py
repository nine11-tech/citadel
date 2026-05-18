from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from citadel.models import Evidence, Finding, Severity


COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
}
SENSITIVE_ENV_WORDS = ("PASSWORD", "TOKEN", "SECRET", "KEY", "API_KEY")
SENSITIVE_PORTS = {"22", "2375", "2376", "3306", "5432", "6379", "9200", "27017"}


def scan_docker_compose(target: str) -> list[Finding]:
    target_path = Path(target)
    compose_file = _find_compose_file(target_path)
    if compose_file is None:
        return []

    try:
        with compose_file.open("r", encoding="utf-8") as file:
            compose_data = yaml.safe_load(file) or {}
    except yaml.YAMLError:
        return []

    if not isinstance(compose_data, dict):
        return []

    services = compose_data.get("services", {})
    if not isinstance(services, dict):
        return []

    findings: list[Finding] = []
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue
        asset = str(service_name)
        findings.extend(_scan_service(asset, service_config, compose_file))

    return findings


def _find_compose_file(target_path: Path) -> Path | None:
    if target_path.is_file() and target_path.name in COMPOSE_FILENAMES:
        return target_path

    if not target_path.is_dir():
        return None

    for filename in COMPOSE_FILENAMES:
        candidate = target_path / filename
        if candidate.is_file():
            return candidate

    return None


def _scan_service(service_name: str, service: dict[str, Any], compose_file: Path) -> list[Finding]:
    findings: list[Finding] = []

    if service.get("privileged") is True:
        findings.append(
            _finding(
                finding_id="DOCKER-001",
                title="Privileged container enabled",
                description="The service runs with privileged container access.",
                severity=Severity.CRITICAL,
                asset=service_name,
                compose_file=compose_file,
                risky_value="privileged: true",
                impact="Privileged containers can bypass normal container isolation controls.",
                remediation="Remove privileged mode and grant only the specific permissions required.",
            )
        )

    for volume in _as_list(service.get("volumes")):
        if "/var/run/docker.sock" in _stringify(volume):
            findings.append(
                _finding(
                    finding_id="DOCKER-002",
                    title="Docker socket mounted into container",
                    description="The service mounts the host Docker socket.",
                    severity=Severity.CRITICAL,
                    asset=service_name,
                    compose_file=compose_file,
                    risky_value=f"volume: {_stringify(volume)}",
                    impact="Access to the Docker socket can allow control of the host Docker daemon.",
                    remediation="Avoid mounting the Docker socket into containers.",
                )
            )

    if service.get("network_mode") == "host":
        findings.append(
            _finding(
                finding_id="DOCKER-003",
                title="Host network mode enabled",
                description="The service uses the host network namespace.",
                severity=Severity.HIGH,
                asset=service_name,
                compose_file=compose_file,
                risky_value="network_mode: host",
                impact="Host networking reduces network isolation between the container and host.",
                remediation="Use a dedicated Docker network instead of host networking.",
            )
        )

    image = service.get("image")
    if isinstance(image, str) and _uses_latest_or_missing_tag(image):
        findings.append(
            _finding(
                finding_id="DOCKER-004",
                title="Image tag is latest or missing",
                description="The service image does not pin an immutable or explicit version tag.",
                severity=Severity.MEDIUM,
                asset=service_name,
                compose_file=compose_file,
                risky_value=f"image: {image}",
                impact="Unpinned images can change unexpectedly and make deployments less reproducible.",
                remediation="Pin images to a specific version tag or digest.",
            )
        )

    user = service.get("user")
    if user is None or str(user) in {"root", "0"}:
        findings.append(
            _finding(
                finding_id="DOCKER-005",
                title="Container runs as root",
                description="The service does not configure a non-root user.",
                severity=Severity.MEDIUM,
                asset=service_name,
                compose_file=compose_file,
                risky_value=f"user: {user if user is not None else '<missing>'}",
                impact="Processes running as root can increase the impact of container compromise.",
                remediation="Set a dedicated non-root user for the service.",
            )
        )

    for capability in _as_list(service.get("cap_add")):
        capability_name = str(capability).upper()
        if capability_name in DANGEROUS_CAPABILITIES:
            findings.append(
                _finding(
                    finding_id="DOCKER-006",
                    title="Dangerous Linux capability added",
                    description="The service adds a high-risk Linux capability.",
                    severity=Severity.HIGH,
                    asset=service_name,
                    compose_file=compose_file,
                    risky_value=f"cap_add: {capability_name}",
                    impact="Extra capabilities can weaken container isolation and expand attack impact.",
                    remediation="Remove unnecessary capabilities and use the least privilege set required.",
                )
            )

    for env_name, env_value in _environment_items(service.get("environment")):
        if any(word in env_name.upper() for word in SENSITIVE_ENV_WORDS):
            findings.append(
                _finding(
                    finding_id="DOCKER-007",
                    title="Sensitive environment variable configured",
                    description="The service appears to define a secret in environment variables.",
                    severity=Severity.HIGH,
                    asset=service_name,
                    compose_file=compose_file,
                    risky_value=f"environment: {env_name}={env_value}",
                    impact="Secrets in Compose files can be exposed through source control or local access.",
                    remediation="Move secrets to a dedicated secrets manager or Docker secrets.",
                )
            )

    for port in _as_list(service.get("ports")) + _as_list(service.get("expose")):
        exposed_ports = _extract_ports(port)
        if exposed_ports & SENSITIVE_PORTS:
            findings.append(
                _finding(
                    finding_id="DOCKER-008",
                    title="Sensitive service port exposed",
                    description="The service exposes a commonly sensitive administrative or data port.",
                    severity=Severity.MEDIUM,
                    asset=service_name,
                    compose_file=compose_file,
                    risky_value=f"port: {_stringify(port)}",
                    impact="Exposed sensitive ports increase the service's attack surface.",
                    remediation="Restrict port exposure to trusted networks or remove unnecessary mappings.",
                )
            )

    if "healthcheck" not in service:
        findings.append(
            _finding(
                finding_id="DOCKER-009",
                title="Missing healthcheck",
                description="The service does not define a container healthcheck.",
                severity=Severity.LOW,
                asset=service_name,
                compose_file=compose_file,
                risky_value="healthcheck: <missing>",
                impact="Missing healthchecks make service failure detection and recovery less reliable.",
                remediation="Add a healthcheck that validates the service is operating correctly.",
            )
        )

    return findings


def _finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    severity: Severity,
    asset: str,
    compose_file: Path,
    risky_value: str,
    impact: str,
    remediation: str,
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        description=description,
        severity=severity,
        category="docker",
        asset=asset,
        evidence=[
            Evidence(
                source="docker-compose",
                output=risky_value,
                file_path=str(compose_file),
            )
        ],
        impact=impact,
        remediation=remediation,
        references=[],
    )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(str(item) for pair in value.items() for item in pair)
    return str(value)


def _uses_latest_or_missing_tag(image: str) -> bool:
    if "@" in image:
        return False

    image_name = image.rsplit("/", maxsplit=1)[-1]
    if ":" not in image_name:
        return True

    return image_name.rsplit(":", maxsplit=1)[-1] == "latest"


def _environment_items(environment: Any) -> list[tuple[str, str]]:
    if isinstance(environment, dict):
        return [(str(name), str(value)) for name, value in environment.items()]

    items: list[tuple[str, str]] = []
    for entry in _as_list(environment):
        if not isinstance(entry, str):
            continue
        name, separator, value = entry.partition("=")
        items.append((name, value if separator else ""))

    return items


def _extract_ports(port: Any) -> set[str]:
    if isinstance(port, int):
        return {str(port)}

    if isinstance(port, dict):
        return {
            str(value)
            for value in (port.get("target"), port.get("published"))
            if value is not None
        }

    if not isinstance(port, str):
        return set()

    port_spec = port.split("/", maxsplit=1)[0]
    return {port_spec.rsplit(":", maxsplit=1)[-1]}
