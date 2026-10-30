"""Tests for defense/classifier/mitigation_report.py, with synthetic recordings and feature log."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "defense" / "classifier"))

import dataset  # noqa: E402
import mitigation_report as report  # noqa: E402

BASE = 2_000_000.0


def write_run(directory: Path, name: str, attack_type: str, start: float, end: float, events: int,
              blocked_from: float | None = None):
    """`events` evenly spread over [start, end]; those at or after `blocked_from` are answered 429."""
    lines = []
    for i in range(events):
        ts = start + (end - start) * i / max(events - 1, 1)
        status = 429 if blocked_from is not None and ts >= blocked_from else 200
        lines.append(json.dumps({"ts": ts, "attack_type": attack_type, "target": "t", "status": status, "latency_ms": 5.0}))
    (directory / f"{name}.jsonl").write_text("\n".join(lines), encoding="utf-8")
    (directory / f"{name}.meta.json").write_text(json.dumps({"start_ts": start, "end_ts": end}), encoding="utf-8")


def log_entries(points: list[tuple[float, float, float]]) -> list[dict]:
    return [{"ts": ts, "confidence": conf, "threshold": limit, "state": "mitigating" if limit < 500 else "normal",
             "features": {}} for ts, conf, limit in points]


@pytest.fixture
def lab(tmp_path):
    # An attack from BASE to BASE+100 (blocked from +30), a legitimate run beside it, then a quiet recovery.
    write_run(tmp_path, "m_fg_floodL", "http_flood", BASE, BASE + 100, events=1000, blocked_from=BASE + 30)
    write_run(tmp_path, "m_fg_floodL_legit", "legitimate_load", BASE + 5, BASE + 95, events=90, blocked_from=BASE + 80)
    write_run(tmp_path, "m_fg_legit", "legitimate_load", BASE + 400, BASE + 500, events=100)
    write_run(tmp_path, "unrelated_run", "http_flood", BASE + 600, BASE + 700, events=10)
    points = []
    for t in range(0, 100, 5):  # confidence flagged, limit stepping down
        points.append((BASE + t, 0.7, max(45.0, 500.0 * 0.4 ** (t / 5))))
    for t in range(105, 140, 5):  # attack over: limit climbs back
        points.append((BASE + t, 0.2, min(500.0, 45.0 * 1.5 ** ((t - 100) / 5 + 1))))
    for t in range(140, 200, 5):
        points.append((BASE + t, 0.2, 500.0))
    for t in range(400, 500, 5):  # legitimate alone: occasional isolated flag, cap untouched
        points.append((BASE + t, 0.6 if t == 450 else 0.3, 500.0))
    return dataset.discover_recordings(tmp_path), log_entries(points)


def rows(infos, log):
    return {(r["config"], r["scenario"]): r for r in report.build_report(infos, log, 500.0)["rows"]}


def test_attack_and_legitimate_blocking_are_measured_from_the_recordings(lab):
    row = rows(*lab)[("fg", "floodL")]
    attack, legit = row["attack"], row["legit"]
    assert attack["requests"] == 1000 and attack["blocked"] == pytest.approx(700, abs=3)
    assert attack["offered_rps"] == pytest.approx(10.0)
    assert attack["admitted_rps"] == pytest.approx(3.0, abs=0.1)
    assert attack["first_block_s"] == pytest.approx(30.1, abs=0.3)
    assert legit["requests"] == 90 and legit["blocked"] == pytest.approx(15, abs=2)
    assert legit["blocked_fraction"] == pytest.approx(legit["blocked"] / 90)


def test_limit_and_flagging_come_from_the_feature_log(lab):
    row = rows(*lab)[("fg", "floodL")]
    assert row["limit"]["min_rps"] == 45.0 and row["limit"]["typical_rps"] == 45.0
    assert row["polls"] > 0 and row["flagged_polls"] == row["polls"] and row["mitigating_polls"] == row["polls"]


def test_recovery_is_the_time_until_the_limit_is_back_near_the_baseline(lab):
    recovery = rows(*lab)[("fg", "floodL")]["recovery"]
    assert recovery["recovered"] is True
    assert 15 <= recovery["seconds"] <= 30  # climbs 45 -> >= 450 over a few polls of 1.5x
    assert recovery["observed_seconds"] > recovery["seconds"]


def test_a_limit_that_never_recovers_is_reported_as_such(lab):
    infos, log = lab
    stuck = [dict(e, threshold=45.0) if e["ts"] >= BASE + 100 and e["ts"] < BASE + 300 else e for e in log]
    recovery = rows(infos, stuck)[("fg", "floodL")]["recovery"]
    assert recovery["recovered"] is False and recovery["seconds"] is None


def test_legitimate_only_run_reports_false_positive_polls_and_an_untouched_limit(lab):
    row = rows(*lab)[("fg", "legit")]
    assert "attack" not in row and "recovery" not in row
    assert row["legit"]["blocked"] == 0 and row["limit"]["min_rps"] == 500.0
    assert row["flagged_polls"] == 1 and row["polls"] > 10  # the one isolated flagged poll


def test_runs_that_do_not_follow_the_scenario_naming_are_ignored(lab):
    assert {key for key in rows(*lab)} == {("fg", "floodL"), ("fg", "legit")}
    assert set(report.build_report(*lab, 500.0)["configs"]) == {"fg"}


def test_steady_rates_and_time_to_engage_exclude_the_pre_mitigation_period(lab):
    row = rows(*lab)[("fg", "floodL")]
    # The flood is blocked from +30s, so nothing gets through in the second half (+50s to +100s)...
    assert row["attack"]["steady_admitted_rps"] == 0.0
    # ...while the whole-run rate still includes the unmitigated first 30 seconds.
    assert row["attack"]["admitted_rps"] > 0
    # The log's limit first falls below half the 500 baseline at t=10 (500 * 0.4**2 = 80 at t=10, 200 at t=5).
    assert row["limit"]["below_half_baseline_s"] == 5.0
    assert row["legit"]["steady_admitted_rps"] > 0  # legitimate requests keep getting through in the second half


def test_runs_with_an_implausible_duration_are_excluded_and_listed(tmp_path):
    # The host was suspended while this one ran: its recording spans hours.
    write_run(tmp_path, "m_fg_dist_1", "http_flood", BASE, BASE + 4000, events=100)
    write_run(tmp_path, "m_fg_dist_7", "http_flood", BASE + 5000, BASE + 5070, events=100)
    result = report.build_report(dataset.discover_recordings(tmp_path), [], 500.0)
    assert [e["run"] for e in result["excluded_runs"]] == ["m_fg_dist_1"]
    assert "suspended" in result["excluded_runs"][0]["reason"]
    (row,) = result["rows"]
    assert row["attack_sources"] == 1 and row["seconds"] == 70.0  # only the valid run defines the scenario


def test_operator_exclusions_and_retry_names_are_supported(tmp_path):
    write_run(tmp_path, "m_fg_floodL", "http_flood", BASE, BASE + 80, events=100)  # contaminated first attempt
    write_run(tmp_path, "m_fg_floodL_legit", "legitimate_load", BASE + 5, BASE + 70, events=60, blocked_from=BASE + 20)
    write_run(tmp_path, "m_fg_floodL_7", "http_flood", BASE + 1000, BASE + 1080, events=100)  # the retry
    write_run(tmp_path, "m_fg_floodL_legit2", "legitimate_load", BASE + 1005, BASE + 1070, events=60)
    exclusions = {"m_fg_floodL": "cap still lowered at start", "m_fg_floodL_legit": "cap still lowered at start"}
    result = report.build_report(dataset.discover_recordings(tmp_path), [], 500.0, exclusions)
    assert {e["run"] for e in result["excluded_runs"]} == set(exclusions)
    (row,) = result["rows"]
    assert row["legit"]["blocked"] == 0 and row["legit"]["requests"] == 60  # the retry, not the contaminated pair
    assert row["attack_sources"] == 1


def test_start_state_and_pre_engagement_blocking_are_recorded(tmp_path):
    # A flood begins while the cap is still lowered from the previous scenario, and a burst is rejected
    # before the engine has done anything: both must be visible, neither is "mitigation working".
    write_run(tmp_path, "m_fg_flood", "http_flood", BASE, BASE + 70, events=100, blocked_from=BASE + 2)
    log = log_entries([(BASE - 1, 0.3, 40.0), (BASE + 4, 0.7, 40.0), (BASE + 9, 0.7, 30.0)])
    row = rows(dataset.discover_recordings(tmp_path), log)[("fg", "flood")]
    assert row["start"] == {"cap_rps": 40.0, "state": "mitigating", "clean": False}

    clean = log_entries([(BASE - 1, 0.3, 500.0), (BASE + 4, 0.7, 500.0), (BASE + 9, 0.7, 200.0)])
    clean[0]["state"] = "normal"
    clean_row = rows(dataset.discover_recordings(tmp_path), clean)[("fg", "flood")]
    assert clean_row["start"]["clean"] is True
    # The cap is first below 90% of the baseline at +9s; everything rejected before that is a burst at the baseline cap.
    before = clean_row["attack"]["blocked_before_engagement"]
    assert before > 0 and before < clean_row["attack"]["blocked"]


def test_a_non_http_attack_is_reported_as_not_blockable(tmp_path):
    write_run(tmp_path, "m_fgc_slowL", "slowloris", BASE, BASE + 80, events=50)
    write_run(tmp_path, "m_fgc_slowL_legit", "legitimate_load", BASE + 5, BASE + 70, events=60, blocked_from=BASE + 50)
    (row,) = report.build_report(dataset.discover_recordings(tmp_path), log_entries([(BASE + 3, 0.7, 20.0)]), 500.0)["rows"]
    assert row["scenario"] == "slowL" and row["attack"]["http"] is False
    assert "blocked" not in row["attack"] and "blocked_fraction" not in row["attack"]
    assert row["legit"]["blocked"] > 0  # the cost to legitimate HTTP clients is still measured


def test_configuration_filter(lab):
    infos, log = lab
    assert report.build_report(infos, log, 500.0, configs=["gl"])["rows"] == []
    assert {r["config"] for r in report.build_report(infos, log, 500.0, configs=["fg"])["rows"]} == {"fg"}
