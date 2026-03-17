import requests
from config import ABUSE_API_KEY, REQUEST_TIMEOUT

BASE_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS  = {"Key": ABUSE_API_KEY, "Accept": "application/json"}

def enrich(ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ip":
        return {"source": "abuseipdb", "skipped": "only supports IPs"}

    try:
        params   = {"ipAddress": ioc, "maxAgeInDays": 90}
        response = requests.get(BASE_URL, headers=HEADERS,
                                params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()["data"]

        return {
            "source": "abuseipdb",
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports":    data.get("totalReports", 0),
            "country_code":     data.get("countryCode", ""),
            "isp":              data.get("isp", ""),
            "is_tor":           data.get("isTor", False)
        }

    except requests.exceptions.RequestException as e:
        return {"source": "abuseipdb", "error": str(e)}
    except (KeyError, ValueError) as e:
        return {"source": "abuseipdb", "error": f"parse error: {str(e)}"}