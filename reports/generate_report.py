"""SENTINEL LAB post-run benchmark report generator.

Reads a simulation recording (attackers/recordings/<run>.jsonl) plus the
mitigation log (defense/mitigation_log.jsonl) and produces an HTML report
covering: attack type, peak requests/sec, detection latency (time from
attack start to first mitigation action), false-positive rate (only
meaningful for legitimate-load control runs), and service degradation
(latency/error-rate delta).

Optionally renders to PDF if `weasyprint` is installed; otherwise the HTML
report is left as the deliverable (it is fully viewable/printable as-is).
"""
import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path

from jinja2 import Template

RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "attackers" / "recordings"
MITIGATION_LOG = Path(__file__).resolve().parent.parent / "defense" / "mitigation_log.jsonl"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "report.html.j2"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_jsonl(path: Path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def summarize(run_name: str, is_control: bool):
    events = load_jsonl(RECORDINGS_DIR / f"{run_name}.jsonl")
    if not events:
        raise SystemExit(f"No recorded events found for run '{run_name}'")

    events.sort(key=lambda e: e["ts"])
    t0 = events[0]["ts"]
    t_end = events[-1]["ts"]
    duration = max(t_end - t0, 1e-6)

    # Peak requests/sec over 1s buckets.
    buckets = {}
    for e in events:
        b = int(e["ts"] - t0)
        buckets[b] = buckets.get(b, 0) + 1
    peak_rps = max(buckets.values()) if buckets else 0

    latencies = [e["latency_ms"] for e in events if e.get("latency_ms") is not None]
    errors = [e for e in events if e.get("status") and e["status"] >= 500]
    error_rate = len(errors) / len(events) if events else 0.0
    avg_latency = statistics.mean(latencies) if latencies else 0.0
    p95_latency = (
        statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else (max(latencies) if latencies else 0.0)
    )

    attack_types = sorted({e["attack_type"] for e in events})

    mitigations = load_jsonl(MITIGATION_LOG)
    mitigations_in_window = [m for m in mitigations if t0 <= m["ts"] <= t_end + 30]
    detection_latency = None
    if mitigations_in_window and not is_control:
        first_mitigation_ts = min(m["ts"] for m in mitigations_in_window)
        detection_latency = max(0.0, first_mitigation_ts - t0)

    false_positive_rate = None
    if is_control:
        # For a legitimate-load control run, every mitigation action fired
        # during the run counts as a false positive.
        false_positive_rate = len(mitigations_in_window) / max(len(buckets), 1)

    return {
        "run_name": run_name,
        "is_control": is_control,
        "attack_types": attack_types,
        "duration_s": round(duration, 1),
        "total_events": len(events),
        "peak_rps": peak_rps,
        "avg_latency_ms": round(avg_latency, 2),
        "p95_latency_ms": round(p95_latency, 2),
        "error_rate": round(error_rate * 100, 2),
        "detection_latency_s": round(detection_latency, 2) if detection_latency is not None else None,
        "false_positive_rate": round(false_positive_rate * 100, 2) if false_positive_rate is not None else None,
        "mitigation_count": len(mitigations_in_window),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def render(summary: dict) -> Path:
    template = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    html = template.render(**summary)
    out_path = OUTPUT_DIR / f"{summary['run_name']}_report.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


def maybe_render_pdf(html_path: Path) -> Path | None:
    try:
        from weasyprint import HTML  # optional dependency
    except ImportError:
        return None
    pdf_path = html_path.with_suffix(".pdf")
    HTML(str(html_path)).write_pdf(str(pdf_path))
    return pdf_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a SENTINEL LAB benchmark report")
    parser.add_argument("run_name")
    parser.add_argument("--control", action="store_true", help="Treat this run as a legitimate-load control run")
    args = parser.parse_args()

    summary = summarize(args.run_name, args.control)
    html_path = render(summary)
    print(f"HTML report written to {html_path}")

    pdf_path = maybe_render_pdf(html_path)
    if pdf_path:
        print(f"PDF report written to {pdf_path}")
    else:
        print("weasyprint not installed -- skipping PDF export (HTML report is still complete)")
