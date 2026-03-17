import json
import csv
import os
from datetime import datetime

OUTPUT_DIR = "output"

def build_report(ioc, ioc_type, vt, abuse, risk) -> dict:
    return {
        "ioc":         ioc,
        "ioc_type":    ioc_type,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "risk_score":  risk["score"],
        "risk_level":  risk["level"],
        "risk_reasons": risk["reasons"],
        "virustotal":  vt,
        "abuseipdb":   abuse
    }

def save_json(report: dict) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    safe_ioc = report["ioc"].replace(".", "_")
    filename = f"{OUTPUT_DIR}/{safe_ioc}_{report['timestamp'][:10]}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename

def save_csv(reports: list, filename="output/batch_results.csv"):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fields = [
        "ioc", "ioc_type", "timestamp",
        "risk_score", "risk_level",
        "vt_malicious", "vt_total", "vt_families",
        "abuse_confidence", "abuse_reports",
        "country", "isp"
    ]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in reports:
            writer.writerow({
                "ioc":              r["ioc"],
                "ioc_type":         r["ioc_type"],
                "timestamp":        r["timestamp"],
                "risk_score":       r["risk_score"],
                "risk_level":       r["risk_level"],
                "vt_malicious":     r["virustotal"].get("malicious_engines", "N/A"),
                "vt_total":         r["virustotal"].get("total_engines", "N/A"),
                "vt_families":      "|".join(r["virustotal"].get("malware_families", [])),
                "abuse_confidence": r["abuseipdb"].get("confidence_score", "N/A"),
                "abuse_reports":    r["abuseipdb"].get("total_reports", "N/A"),
                "country":          r["abuseipdb"].get("country_code", "N/A"),
                "isp":              r["abuseipdb"].get("isp", "N/A")
            })
    return filename