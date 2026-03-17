import requests
from config import VT_API_KEY, REQUEST_TIMEOUT

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS  = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

def enrich(ioc: str, ioc_type: str) -> dict:
    try:
        if ioc_type == "ip":
            url = f"{BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "hash":
            url = f"{BASE_URL}/files/{ioc}"
        else:
            return {"source": "virustotal", "error": "unsupported type"}

        response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        stats      = data["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious", 0)
        total      = sum(stats.values())

        families = []
        results  = data["data"]["attributes"].get("last_analysis_results", {})
        for engine, result in results.items():
            if result.get("category") == "malicious":
                name = result.get("result")
                if name and name not in families:
                    families.append(name)

        return {
            "source": "virustotal",
            "malicious_engines": malicious,
            "total_engines": total,
            "detection_ratio": round(malicious / total, 2) if total > 0 else 0,
            "malware_families": families[:5]
        }

    except requests.exceptions.RequestException as e:
        return {"source": "virustotal", "error": str(e)}
    except (KeyError, ValueError) as e:
        return {"source": "virustotal", "error": f"parse error: {str(e)}"}