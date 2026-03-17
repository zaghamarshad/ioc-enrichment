# IOC Enrichment Pipeline

A Python-based threat intelligence tool that automates investigation of suspicious IPs and file hashes by querying multiple threat intel APIs and generating structured risk reports.

Built as a SOC home lab project to simulate real analyst triage workflows.

---

## Features

- Supports IP addresses and file hashes (MD5, SHA1, SHA256)
- Queries VirusTotal and AbuseIPDB APIs in parallel using ThreadPoolExecutor
- Weighted risk scoring engine (0–100) with severity levels
- JSON report output per IOC with timestamp
- Batch processing via CSV input for multi-IOC triage
- Graceful per-enricher error handling — one API failure does not break the pipeline
- API keys stored securely in `.env` — never hardcoded

---

## Architecture

```
Input (IP or Hash)
        ↓
   detector.py  →  identifies IOC type via regex
        ↓
  ┌─────┴──────┐
  │  parallel  │
  ▼            ▼
virustotal.py  abuseipdb.py
  │            │
  └─────┬──────┘
        ↓
   scorer.py   →  weighted risk score (VT: 60pts, AbuseIPDB: 40pts)
        ↓
  reporter.py  →  JSON report + CSV batch export
```

---

## File Structure

```
ioc-enrichment/
├── main.py                  # Entry point — single IOC investigation
├── config.py                # Loads API keys from .env
├── detector.py              # IOC type detection via regex
├── enrichers/
│   ├── __init__.py
│   ├── virustotal.py        # VirusTotal API enricher
│   └── abuseipdb.py         # AbuseIPDB API enricher
├── core/
│   ├── __init__.py
│   ├── scorer.py            # Risk scoring engine
│   └── reporter.py          # JSON + CSV output
├── batch.py                 # Batch CSV processor
├── requirements.txt
├── .env                     # API keys (never committed)
└── .gitignore
```

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/zaghamarshad/ioc-enrichment-pipeline.git
cd ioc-enrichment-pipeline
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API keys

Create a `.env` file in the project root:

```
VT_API_KEY=your_virustotal_key
ABUSE_API_KEY=your_abuseipdb_key
```

Get free API keys from:
- VirusTotal: https://www.virustotal.com
- AbuseIPDB: https://www.abuseipdb.com

---

## Usage

### Single IOC — IP address

```bash
python main.py 185.220.101.45
```

### Single IOC — file hash

```bash
python main.py 44d88612fea8a8f36de82e1278abb02f
```

### Batch processing

```bash
python batch.py iocs.csv
```

CSV must contain a column with header `ioc`. Example:

```
ioc
185.220.101.45
44d88612fea8a8f36de82e1278abb02f
8.8.8.8
```

---

## Sample Output

```json
{
  "ioc": "185.220.101.45",
  "ioc_type": "ip",
  "timestamp": "2025-03-10T14:22:05Z",
  "risk_score": 87,
  "risk_level": "CRITICAL",
  "risk_reasons": [
    "VT flagged by 32/70 engines",
    "AbuseIPDB confidence: 95%",
    "IP is a Tor exit node"
  ],
  "virustotal": {
    "malicious_engines": 32,
    "total_engines": 70,
    "detection_ratio": 0.46,
    "malware_families": ["Mirai", "Hajime"]
  },
  "abuseipdb": {
    "confidence_score": 95,
    "total_reports": 847,
    "country_code": "DE",
    "isp": "Tor Project",
    "is_tor": true
  }
}
```

---

## Risk Scoring

| Score  | Level    | Logic                                      |
|--------|----------|--------------------------------------------|
| 75–100 | CRITICAL | High VT detections + high abuse confidence |
| 50–74  | HIGH     | Moderate detections or high abuse reports  |
| 25–49  | MEDIUM   | Low detections or low confidence score     |
| 0–24   | LOW      | Clean across both sources                  |

Scoring weights:
- VirusTotal detection ratio → up to **60 points**
- AbuseIPDB confidence score → up to **40 points**
- Tor exit node bonus penalty → **+5 points**

---

## IOC Types Supported

| Type    | VirusTotal | AbuseIPDB |
|---------|------------|-----------|
| IP      | Yes        | Yes       |
| MD5     | Yes        | Skipped   |
| SHA1    | Yes        | Skipped   |
| SHA256  | Yes        | Skipped   |

AbuseIPDB only supports IP addresses. Hash lookups route to VirusTotal only and are scored accordingly.

---

## Technologies

Python · VirusTotal API · AbuseIPDB API · REST APIs · Threat Intelligence · IOC Analysis · SIEM Integration · Security Automation

---

## Future Improvements

- Splunk HEC integration to forward enriched IOC data into a SIEM dashboard
- Add Shodan enrichment for open port and CVE data
- MITRE ATT&CK technique mapping based on malware families detected
- Web dashboard for visualizing batch report results
- SQLite local caching to avoid redundant API calls on repeated IOCs

---

## Author

**Zagham Arshad**
- LinkedIn: https://linkedin.com/in/zaghamarshad
- GitHub: https://github.com/zaghamarshad
