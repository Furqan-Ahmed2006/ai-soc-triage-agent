from typing import Any, Dict, List


PRIVILEGED_USER_TOKENS = {
    "admin",
    "administrator",
    "root",
    "sysadmin",
    "svc_deploy",
    "iam_admin",
    "superuser",
}

LOCAL_IOC_INTEL: Dict[str, Dict[str, Any]] = {
    "185.220.101.42": {"status": "known_malicious", "label": "Tor Exit / Brute-Force Infrastructure"},
    "45.155.205.99": {"status": "known_malicious", "label": "Credential Stuffing Source"},
    "10.0.0.1": {"status": "internal_infrastructure", "label": "Internal Gateway"},
}


def lookup_ip_intel(ip: str) -> Dict[str, Any]:
    if not ip:
        return {"indicator": None, "status": "missing", "note": "No IP supplied."}
    if ip in LOCAL_IOC_INTEL:
        return {"indicator": ip, **LOCAL_IOC_INTEL[ip]}
    # Unknown IOC is NEVER declared malicious or safe automatically
    return {
        "indicator": ip,
        "status": "unknown",
        "note": "Indicator not present in local IOC snapshot; treated as unverified.",
    }


def _is_privileged(username: str) -> bool:
    u = (username or "").strip().lower()
    return u in PRIVILEGED_USER_TOKENS or u.startswith("admin") or u.startswith("svc_")


def calculate_deterministic_risk(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes deterministic weighted risk score (0-100) strictly from observed evidence."""
    if not events:
        return {
            "score": 0,
            "severity": "Insufficient Evidence",
            "factors": [],
            "ioc_findings": [],
            "recommendation_mode": "advisory_only",
        }

    score = 0
    factors: List[Dict[str, Any]] = []

    failed_events = [e for e in events if e.get("event_type") == "failed_login"]
    success_events = [e for e in events if e.get("event_type") == "successful_login"]
    priv_esc_events = [e for e in events if e.get("event_type") == "privilege_escalation"]

    unique_users = sorted({e.get("username") for e in events if e.get("username")})
    unique_ips = sorted({e.get("source_ip") for e in events if e.get("source_ip")})

    # Factor 1: Repeated authentication failures
    if len(failed_events) >= 5:
        score += 30
        factors.append({
            "rule": "repeated_auth_failures",
            "weight": 30,
            "evidence": f"{len(failed_events)} failed login attempts detected.",
        })
    elif len(failed_events) >= 2:
        score += 15
        factors.append({
            "rule": "multiple_auth_failures",
            "weight": 15,
            "evidence": f"{len(failed_events)} failed login attempts detected.",
        })

    # Factor 2: Failed attempts followed by successful login (possible compromise)
    failed_pairs = {(e.get("source_ip"), e.get("username")) for e in failed_events}
    compromise_matches = [
        e for e in success_events
        if (e.get("source_ip"), e.get("username")) in failed_pairs and len(failed_events) >= 2
    ]
    if compromise_matches:
        score += 35
        factors.append({
            "rule": "failure_followed_by_success",
            "weight": 35,
            "evidence": f"Successful login observed after repeated failures for {len(compromise_matches)} event(s).",
        })

    # Factor 3: Multiple accounts targeted from same activity set
    if len(unique_users) >= 3:
        score += 20
        factors.append({
            "rule": "password_spraying_multi_account",
            "weight": 20,
            "evidence": f"{len(unique_users)} distinct accounts observed: {unique_users[:5]}",
        })

    # Factor 4: Privileged account involved
    priv_users = [u for u in unique_users if _is_privileged(u)]
    if priv_users:
        score += 20
        factors.append({
            "rule": "privileged_account_targeted",
            "weight": 20,
            "evidence": f"Privileged account(s) involved: {priv_users}",
        })

    # Factor 5: Privilege escalation event
    if priv_esc_events:
        score += 25
        factors.append({
            "rule": "privilege_escalation_activity",
            "weight": 25,
            "evidence": f"{len(priv_esc_events)} privilege escalation event(s) present.",
        })

    # Factor 6: Known malicious IOC (unknown IOC adds 0 and stays explicitly unknown)
    ioc_findings = [lookup_ip_intel(ip) for ip in unique_ips]
    malicious_ips = [i["indicator"] for i in ioc_findings if i.get("status") == "known_malicious"]
    if malicious_ips:
        score += 25
        factors.append({
            "rule": "known_malicious_ioc",
            "weight": 25,
            "evidence": f"Matched known malicious IP(s): {malicious_ips}",
        })

    score = min(score, 100)
    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "factors": factors,
        "ioc_findings": ioc_findings,
        "recommendation_mode": "advisory_only_human_review",
    }