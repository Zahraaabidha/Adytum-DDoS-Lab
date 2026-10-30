"""The selected default model and mitigation policy must be configured the same way in Docker and in the code.

Parses docker-compose.yml with regular expressions (the CI test job does not install PyYAML).
"""
import re
import sys
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))
sys.path.insert(0, str(ROOT / "defense" / "rate_limiter"))

COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def compose_default(variable: str) -> str:
    match = re.search(rf"^\s+{variable}: \$\{{[A-Z_]+:-([^}}]+)\}}", COMPOSE, re.M)
    assert match, f"{variable} has no `${{NAME:-default}}` entry in docker-compose.yml"
    return match.group(1)


def test_docker_defaults_match_the_code_defaults():
    import engine
    import proxy

    assert compose_default("MODEL_PATH") == engine.DEFAULT_MODEL_PATH
    assert compose_default("EVALUATION_PATH") == engine.DEFAULT_EVALUATION_PATH
    assert compose_default("MITIGATION_POLICY") == "guarded" == engine.MITIGATION_POLICY
    assert compose_default("LIMITER_MODE") == "fair" == proxy.LIMITER_MODE
    from mitigation import GuardedPolicy

    assert float(compose_default("MITIGATION_HEADROOM")) == engine.GUARD_HEADROOM == GuardedPolicy(500.0, 20.0).headroom == 6.0


def test_the_selected_default_is_the_candidate_and_the_original_is_not_the_default():
    import engine

    assert Path(engine.DEFAULT_MODEL_PATH).name == "model.candidate.joblib"
    assert Path(engine.DEFAULT_EVALUATION_PATH).name == "evaluation.candidate.json"
    assert Path(engine.DEFAULT_MODEL_PATH).name != "model.joblib"  # the rollback model is never the thing a default run writes or loads


def test_rollback_is_one_documented_variable():
    assert "SENTINEL_MODEL_PATH=/app/classifier/model.joblib" in COMPOSE
    assert "SENTINEL_MODEL_PATH" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_health_reports_the_loaded_model_and_the_policy(tmp_path, monkeypatch):
    import engine
    from classifier.live_features import LIVE_FEATURE_NAMES
    from fastapi.testclient import TestClient

    path = tmp_path / "model.candidate.joblib"
    model = IsolationForest(random_state=0).fit([[float(i)] * 6 for i in range(30)])
    joblib.dump({"model": model, "feature_names": LIVE_FEATURE_NAMES, "legit_runs": ["a", "b"], "samples": 30,
                 "trained_at": "2026-10-29T16:00:00+00:00", "idle_windows": [(1.0, 2.0)], "contamination": 0.005}, path)
    monkeypatch.setattr(engine, "MODEL_PATH", path)
    loaded = engine._load_model()
    monkeypatch.setattr(engine, "_model", loaded)
    health = TestClient(engine.app).get("/health").json()
    assert health["model_loaded"] is True and health["policy"] == engine.MITIGATION_POLICY
    assert health["model"] == {"file": "model.candidate.joblib", "trained_at": "2026-10-29T16:00:00+00:00", "samples": 30,
                               "legit_runs": ["a", "b"], "idle_windows": 1, "contamination": 0.005}


def test_a_missing_model_is_visible_in_health_not_silent(tmp_path, monkeypatch):
    import engine
    from fastapi.testclient import TestClient

    monkeypatch.setattr(engine, "MODEL_PATH", tmp_path / "does-not-exist.joblib")
    monkeypatch.setattr(engine, "_model", engine._load_model())
    monkeypatch.setattr(engine, "_model_info", None)
    health = TestClient(engine.app).get("/health").json()
    assert health["model_loaded"] is False and health["model"] is None
