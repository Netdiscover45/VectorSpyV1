def calculate_risk(port, service, version=""):

    port = int(port)

    service = (service or "").lower()
    version = (version or "").lower()

    # Default values
    severity = "Low"
    score = 2
    recommendation = "Review this service and keep it updated."

    # High-risk services
    if port in [21, 23, 445]:
        severity = "High"
        score = 8
        recommendation = "Restrict access and disable the service if not required."

    # Medium-risk services
    elif port in [22, 25, 53, 80, 110, 139, 143, 3389]:
        severity = "Medium"
        score = 5
        recommendation = "Review configuration and restrict unnecessary access."

    # Web services
    elif port in [443, 8080, 8443]:
        severity = "Medium"
        score = 4
        recommendation = "Review web configuration, TLS settings and security headers."

    # Service-based checks
    if "telnet" in service:
        severity = "High"
        score = 9
        recommendation = "Disable Telnet and use SSH instead."

    elif "ftp" in service:
        severity = "High"
        score = 8
        recommendation = "Use secure file transfer such as SFTP."

    return {
        "severity": severity,
        "score": score,
        "recommendation": recommendation
    }