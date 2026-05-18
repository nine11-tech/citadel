from pathlib import Path

from citadel.models import Finding
from citadel.scanners.docker import scan_docker_compose


def write_compose(target: Path, content: str) -> None:
    target.joinpath("docker-compose.yml").write_text(content, encoding="utf-8")


def finding_ids(target: Path) -> set[str]:
    return {finding.id for finding in scan_docker_compose(str(target))}


def test_no_compose_file_returns_empty_list(tmp_path: Path) -> None:
    assert scan_docker_compose(str(tmp_path)) == []


def test_vulnerable_compose_detects_privileged_container(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:1.25
    privileged: true
    user: "1000"
    healthcheck:
      test: ["CMD", "true"]
""",
    )

    assert "DOCKER-001" in finding_ids(tmp_path)


def test_vulnerable_compose_detects_docker_sock_mount(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:1.25
    user: "1000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    healthcheck:
      test: ["CMD", "true"]
""",
    )

    assert "DOCKER-002" in finding_ids(tmp_path)


def test_vulnerable_compose_detects_latest_image(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:latest
    user: "1000"
    healthcheck:
      test: ["CMD", "true"]
""",
    )

    assert "DOCKER-004" in finding_ids(tmp_path)


def test_vulnerable_compose_detects_secret_environment_variable(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:1.25
    user: "1000"
    environment:
      API_KEY: insecure-demo-key
    healthcheck:
      test: ["CMD", "true"]
""",
    )

    assert "DOCKER-007" in finding_ids(tmp_path)


def test_vulnerable_compose_detects_sensitive_port(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:1.25
    user: "1000"
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD", "true"]
""",
    )

    assert "DOCKER-008" in finding_ids(tmp_path)


def test_findings_are_valid_finding_objects(tmp_path: Path) -> None:
    write_compose(
        tmp_path,
        """
services:
  app:
    image: nginx:latest
""",
    )

    findings = scan_docker_compose(str(tmp_path))

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)
