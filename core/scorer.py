def calculate_risk_score(vt: dict, abuse: dict) -> dict:
    """
    VirusTotal → 60 pts
    AbuseIPDB  → 40 pts
    Max        → 100 pts
    """
    score   = 0
    reasons = []

    # VirusTotal (60 pts)
    if "error" not in vt and "skipped" not in vt:
        ratio    = vt.get("detection_ratio", 0)
        vt_score = ratio * 60
        score   += vt_score
        if ratio > 0.3:
            reasons.append(
                f"VT flagged by {vt['malicious_engines']}/{vt['total_engines']} engines"
            )
        if vt.get("malware_families"):
            reasons.append(
                f"Malware families: {', '.join(vt['malware_families'][:2])}"
            )

    # AbuseIPDB (40 pts)
    if "error" not in abuse and "skipped" not in abuse:
        confidence   = abuse.get("confidence_score", 0)
        abuse_score  = (confidence / 100) * 40
        score       += abuse_score
        if confidence > 25:
            reasons.append(f"AbuseIPDB confidence: {confidence}%")
        if abuse.get("is_tor"):
            reasons.append("IP is a Tor exit node")
            score += 5

    score = round(min(score, 100))

    if score >= 75:   level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    else:             level = "LOW"

    return {"score": score, "level": level, "reasons": reasons}