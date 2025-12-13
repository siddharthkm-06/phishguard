
import json
import os
from typing import Dict, Any
from core.rules import apply_all_rules

# Load thresholds/config from data/thresholds.json if present
DEFAULT_THRESHOLDS = {
    "severity": {"high": 60, "medium": 25, "low": 0},
    "similarity_thresholds": {"strong": 80, "moderate": 60},
    "weights": {}
}

def load_config():
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cfg_path = os.path.join(base, "data", "thresholds.json")
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return cfg
        except Exception:
            return DEFAULT_THRESHOLDS
    return DEFAULT_THRESHOLDS

CONFIG = load_config()


# -------------------------------------------------------------------
# SCORING LOGIC
# -------------------------------------------------------------------

def score_url(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply rules and compute a final numeric score and classification.
    """
    results = apply_all_rules(parsed)
    total = sum(r[0] for r in results)
    details = [r[1] for r in results]

    # Normalize score
    if total < 0:
        total = 0
    if total > 100:
        total = 100

    high_cut = CONFIG.get("severity", {}).get("high", 60)
    med_cut = CONFIG.get("severity", {}).get("medium", 25)

    if total >= high_cut:
        severity = "HIGH"
    elif total >= med_cut:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    report = {
        "url": parsed.get("normalized"),
        "score": total,
        "severity": severity,
        "issues": details,
        "parsed": parsed,
    }
    return report


# -------------------------------------------------------------------
# SUMMARY GENERATOR
# -------------------------------------------------------------------

def summarize_report(report: Dict[str, Any]) -> str:
    """
    Human-friendly explanation of the risk.
    """
    severity = report.get("severity")
    issues = report.get("issues", [])

    if severity == "LOW":
        if not issues:
            return "No suspicious indicators found. URL appears safe."
        return "Minor indicators detected, but overall risk is low."

    if severity == "MEDIUM":
        return "Several suspicious indicators detected. Exercise caution with this URL."

    if severity == "HIGH":
        return "Strong phishing indicators detected. This URL is very likely malicious."

    return "Unable to classify risk."


# -------------------------------------------------------------------
# PRETTY PRINT
# -------------------------------------------------------------------

def pretty_print_report(report: Dict[str, Any]) -> None:
    print("=" * 60)
    print(f"URL: {report.get('url')}")
    print(f"Risk Score: {report.get('score')} ({report.get('severity')})")
    print("Detected Issues:")

    if report.get("issues"):
        for idx, issue in enumerate(report.get("issues"), 1):
            print(f" {idx}. {issue}")
    else:
        print(" None")

    # NEW SUMMARY BLOCK
    print("\nSummary:")
    print(" ", summarize_report(report))
    print("=" * 60)


# -------------------------------------------------------------------
# JSON EXPORT
# -------------------------------------------------------------------

def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)
