"""Unit tests for globe/server.py's attack start/stop controls.

`subprocess.run` is mocked, so no Docker is needed.
"""
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "globe"))

import server  # noqa: E402


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture
def docker_calls(monkeypatch):
    """Records every docker command; `running` controls what `docker ps` reports."""
    calls: list[list[str]] = []
    state = {"running": False}

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "ps"]:
            return completed(stdout="attacker-http-flood\n" if state["running"] else "")
        return completed()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    return calls, state


def compose_verbs(calls):
    return [c[c.index("--profile") + 2] for c in calls if c[:2] == ["docker", "compose"]]


def test_start_removes_stale_container_before_up(docker_calls):
    calls, _ = docker_calls
    resp = TestClient(server.app).post("/api/attacks/http-flood/start")
    assert resp.status_code == 200
    assert compose_verbs(calls) == ["rm", "up"]
    rm_cmd = next(c for c in calls if "rm" in c)
    assert rm_cmd[-3:] == ["-f", "-s", "attacker-http-flood"]


def test_start_leaves_running_container_alone(docker_calls):
    calls, state = docker_calls
    state["running"] = True
    resp = TestClient(server.app).post("/api/attacks/http-flood/start")
    assert resp.status_code == 200
    assert compose_verbs(calls) == ["up"]


def test_start_unknown_attack_is_404(docker_calls):
    calls, _ = docker_calls
    assert TestClient(server.app).post("/api/attacks/nope/start").status_code == 404
    assert calls == []


def test_start_reports_compose_failure(monkeypatch):
    def fake_run(cmd, **kwargs):
        if "up" in cmd:
            return completed(returncode=1, stderr="network not found")
        return completed()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    resp = TestClient(server.app).post("/api/attacks/http-flood/start")
    assert resp.status_code == 500
    assert "network not found" in resp.json()["detail"]
