import sys
import json
import concurrent.futures
from detector import detect_ioc_type
from enrichers import virustotal, abuseipdb
from core.scorer import calculate_risk_score
from core.reporter import build_report, save_json

def investigate(ioc: str) -> dict:
    print(f"\n[*] Investigating: {ioc}")

    ioc_type = detect_ioc_type(ioc)
    print(f"[*] Type: {ioc_type}")

    if ioc_type == "unknown":
        print("[!] Unknown IOC type. Only IPs and hashes supported.")
        return {}

    # Run both enrichers in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        vt_future    = executor.submit(virustotal.enrich, ioc, ioc_type)
        abuse_future = executor.submit(abuseipdb.enrich, ioc, ioc_type)
        vt_data      = vt_future.result()
        abuse_data   = abuse_future.result()

    risk   = calculate_risk_score(vt_data, abuse_data)
    report = build_report(ioc, ioc_type, vt_data, abuse_data, risk)
    path   = save_json(report)

    print(f"[*] Risk: {risk['level']} ({risk['score']}/100)")
    print(f"[*] Saved: {path}")
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <ip_or_hash>")
        print("Examples:")
        print("  python main.py 185.220.101.45")
        print("  python main.py 44d88612fea8a8f36de82e1278abb02f")
        sys.exit(1)

    report = investigate(sys.argv[1])

    if report:
        print("\n--- RESULT ---")
        print(json.dumps({
            "ioc":        report["ioc"],
            "type":       report["ioc_type"],
            "risk_level": report["risk_level"],
            "risk_score": report["risk_score"],
            "reasons":    report["risk_reasons"]
        }, indent=2))