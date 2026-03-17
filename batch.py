import csv
import sys
from main import investigate
from core.reporter import save_csv

def process_batch(input_file: str):
    reports = []

    with open(input_file, "r") as f:
        reader = csv.DictReader(f)
        iocs   = [row["ioc"].strip() for row in reader if row.get("ioc")]

    print(f"[*] Processing {len(iocs)} IOCs...")

    for ioc in iocs:
        report = investigate(ioc)
        if report:
            reports.append(report)

    if reports:
        out = save_csv(reports)
        print(f"\n[*] Done. Results: {out}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python batch.py iocs.csv")
        sys.exit(1)
    process_batch(sys.argv[1])
