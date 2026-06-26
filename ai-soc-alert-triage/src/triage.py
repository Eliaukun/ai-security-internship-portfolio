import argparse
import json
import re
from pathlib import Path
from typing import Any


TACTIC_RULES = [
    {
        "name": "Initial Access",
        "patterns": [r"union select", r"thinkphp", r"fastjson", r"weblogic", r"shiro"],
        "weight": 18,
        "next_step": "Validate exploitability, inspect request source, and check adjacent web logs.",
    },
    {
        "name": "Execution",
        "patterns": [r"bash -i", r"powershell", r"cmd\.exe", r"/dev/tcp", r"shell\.jsp"],
        "weight": 28,
        "next_step": "Collect process tree, command line, parent process, and endpoint telemetry.",
    },
    {
        "name": "Credential Access",
        "patterns": [r"failed login", r"then success", r"password", r"service account"],
        "weight": 20,
        "next_step": "Review account history, reset exposed credentials, and check lateral movement traces.",
    },
    {
        "name": "Exfiltration",
        "patterns": [r"customer_export", r"backup", r"upload", r"curl", r"wget"],
        "weight": 22,
        "next_step": "Check outbound traffic, destination reputation, and sensitive data access scope.",
    },
    {
        "name": "Persistence",
        "patterns": [r"webshell", r"shell\.jsp", r"startup", r"cron"],
        "weight": 24,
        "next_step": "Search for persistence files, scheduled tasks, and unexpected web directories.",
    },
]


EVENT_WEIGHTS = {
    "web_request": 12,
    "process_network": 25,
    "auth": 16,
    "file_write": 22,
    "file_access": 15,
    "scanner": -8,
}


def normalize_alert(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(raw.get("id", "unknown")),
        "timestamp": raw.get("timestamp", ""),
        "asset": raw.get("asset", "unknown"),
        "asset_criticality": int(raw.get("asset_criticality", 1)),
        "event_type": raw.get("event_type", "unknown"),
        "src_ip": raw.get("src_ip", ""),
        "dst_ip": raw.get("dst_ip", ""),
        "payload": raw.get("payload", ""),
        "confidence": float(raw.get("confidence", 0.5)),
    }


def match_tactics(payload: str) -> tuple[list[str], list[str], int]:
    tactics = []
    next_steps = []
    score = 0
    for rule in TACTIC_RULES:
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in rule["patterns"]):
            tactics.append(rule["name"])
            next_steps.append(rule["next_step"])
            score += int(rule["weight"])
    return tactics, next_steps, score


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def triage_alert(raw: dict[str, Any]) -> dict[str, Any]:
    alert = normalize_alert(raw)
    tactics, next_steps, tactic_score = match_tactics(alert["payload"])

    priority = 0
    priority += alert["asset_criticality"] * 8
    priority += EVENT_WEIGHTS.get(alert["event_type"], 0)
    priority += tactic_score
    priority = round(priority * max(alert["confidence"], 0.1))

    if alert["event_type"] == "scanner" and alert["confidence"] < 0.5:
        priority = min(priority, 12)

    severity = severity_from_score(priority)
    if not tactics:
        tactics = ["Reconnaissance" if alert["event_type"] == "scanner" else "Unclassified"]
        next_steps = ["Correlate with nearby alerts and verify whether the event is expected."]

    summary = (
        f"{alert['asset']} received {alert['event_type']} activity from {alert['src_ip']} "
        f"with {alert['confidence']:.0%} confidence; mapped tactics: {', '.join(tactics)}."
    )

    return {
        "id": alert["id"],
        "timestamp": alert["timestamp"],
        "asset": alert["asset"],
        "priority": priority,
        "severity": severity,
        "tactics": tactics,
        "summary": summary,
        "next_steps": sorted(set(next_steps)),
        "evidence": alert["payload"][:240],
    }


def load_alerts(path: Path) -> list[dict[str, Any]]:
    alerts = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL on line {line_no}: {exc}") from exc
    return alerts


def print_table(results: list[dict[str, Any]]) -> None:
    print(f"{'id':8} {'severity':9} {'priority':8} {'asset':14} tactics")
    print("-" * 76)
    for item in results:
        print(f"{item['id']:8} {item['severity']:9} {item['priority']:<8} {item['asset'][:14]:14} {', '.join(item['tactics'])}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage SOC alerts from JSONL.")
    parser.add_argument("--input", required=True, help="Path to JSONL alerts.")
    parser.add_argument("--top", type=int, default=0, help="Show top N alerts after sorting.")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    args = parser.parse_args()

    results = [triage_alert(alert) for alert in load_alerts(Path(args.input))]
    results.sort(key=lambda item: item["priority"], reverse=True)
    if args.top:
        results = results[: args.top]

    if args.format == "json":
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_table(results)


if __name__ == "__main__":
    main()

