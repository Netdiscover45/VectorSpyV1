
from flask import Flask, render_template, request, redirect, session, Response
from werkzeug.security import check_password_hash
from datetime import timedelta

from scanners.nmap_scanner import scan_target

from database.db import (
    init_database,
    create_user,
    get_user_by_username,
    create_scan,
    save_finding,
    save_web_finding,
    save_technology,
    save_technology_finding,
    get_scan_history,
    delete_scan,
    get_dashboard_stats,
    get_all_findings,
    get_technology_history,
    get_findings_by_scan,
    get_connection
)

from core.risk_engine import calculate_risk
from scanners.technology_finder import find_technologies
from scanners.web_scanner import scan_web

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
import os
import socket
import sqlite3
# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = "vectorspy-random-secret-key-change-this"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

app.permanent_session_lifetime = timedelta(hours=2)


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_database()


# ============================================================
# LOADING PAGE
# ============================================================

@app.route("/")
def loading():

    return render_template(
        "loading.html"
    )


# ============================================================
# WELCOME PAGE
# ============================================================

@app.route("/welcome")
def welcome():

    return render_template(
        "welcome.html"
    )


# ============================================================
# SIGN IN / LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "name",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        remember = (
            request.form.get("remember") == "1"
        )


        # ----------------------------------------------------
        # EMPTY FIELD CHECK
        # ----------------------------------------------------

        if not username or not password:

            return render_template(
                "login.html",
                error="Please enter username and password."
            )


        # ----------------------------------------------------
        # FIND USER
        # ----------------------------------------------------

        user = get_user_by_username(
            username
        )


        # ----------------------------------------------------
        # VERIFY PASSWORD
        # ----------------------------------------------------

        if not user:

            return render_template(
                "login.html",
                error="Invalid username or password."
            )


        if not check_password_hash(
            user["password_hash"],
            password
        ):

            return render_template(
                "login.html",
                error="Invalid username or password."
            )


        # ----------------------------------------------------
        # CREATE NEW SESSION
        # ----------------------------------------------------

        session.clear()

        session.permanent = remember

        session["user_id"] = user["id"]

        session["user_name"] = user["username"]


        return redirect(
            "/dashboard"
        )


    return render_template(
        "login.html"
    )


# ============================================================
# SIGN UP / CREATE ACCOUNT
# ============================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get(
            "name",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ----------------------------------------------------
        # USERNAME CHECK
        # ----------------------------------------------------

        if not username:

            return render_template(
                "signup.html",
                error="Please enter a username."
            )


        if len(username) < 3:

            return render_template(
                "signup.html",
                error="Username must contain at least 3 characters."
            )


        if len(username) > 50:

            return render_template(
                "signup.html",
                error="Username is too long."
            )


        # ----------------------------------------------------
        # PASSWORD CHECK
        # ----------------------------------------------------

        if not password:

            return render_template(
                "signup.html",
                error="Please enter a password."
            )


        if len(password) < 8:

            return render_template(
                "signup.html",
                error="Password must contain at least 8 characters."
            )


        # ----------------------------------------------------
        # CONFIRM PASSWORD
        # ----------------------------------------------------

        if password != confirm_password:

            return render_template(
                "signup.html",
                error="Passwords do not match."
            )


        # ----------------------------------------------------
        # CHECK EXISTING USER
        # ----------------------------------------------------

        existing_user = get_user_by_username(
            username
        )


        if existing_user:

            return render_template(
                "signup.html",
                error="Username already exists."
            )


        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        user_id = create_user(
            username,
            password
        )


        if user_id is None:

            return render_template(
                "signup.html",
                error="Unable to create account. Please try another username."
            )


        # ----------------------------------------------------
        # ACCOUNT CREATED
        # ----------------------------------------------------

        return redirect(
            "/login?created=1"
        )


    return render_template(
        "signup.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    name = session["user_name"]

    stats = get_dashboard_stats(session["user_id"])

    history = get_scan_history(session["user_id"])


    return render_template(
        "dashboard.html",
        name=name,
        stats=stats,
        history=history
    )


# ============================================================
# NETWORK SCAN
# ============================================================

@app.route("/network-scan", methods=["GET", "POST"])
def network_scan():

    if "user_name" not in session:
        return redirect("/login")

    results = []
    target = ""
    scan_id = None

    # New Nmap options
    scan_mode = "balanced"
    port_filter = ""

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        scan_mode = request.form.get(
            "scan_mode",
            "balanced"
        ).strip()

        port_filter = request.form.get(
            "port_filter",
            ""
        ).strip()

        if target:

            # Send scan mode + custom ports to Nmap scanner
            results = scan_target(
                target,
                scan_mode=scan_mode,
                port_filter=port_filter
            )

            scan_id = create_scan(
                user_id=session["user_id"],
                target=target,
                scan_type="Nmap"
            )

            for host in results:

                if "error" in host:
                    continue

                for port in host.get(
                    "ports",
                    []
                ):

                    risk = calculate_risk(
                        port["port"],
                        port.get(
                            "service",
                            ""
                        ),
                        port.get(
                            "version",
                            ""
                        )
                    )

                    port["severity"] = (
                        risk["severity"]
                    )

                    port["risk_score"] = (
                        risk["score"]
                    )

                    port["recommendation"] = (
                        risk["recommendation"]
                    )

                    save_finding(
                        scan_id=scan_id,
                        port=port["port"],
                        service=port.get(
                            "service",
                            ""
                        ),
                        version=port.get(
                            "version",
                            ""
                        ),
                        severity=risk["severity"],
                        risk_score=risk["score"],
                        recommendation=risk["recommendation"]
                    )

    return render_template(
        "network_scan.html",
        name=session["user_name"],
        target=target,
        results=results,
        scan_id=scan_id,

        # Send these back to HTML
        scan_mode=scan_mode,
        port_filter=port_filter
    )


# ============================================================
# SCAN
# ============================================================

@app.route("/scan", methods=["GET", "POST"])
def scan():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    if request.method == "GET":

        return redirect(
            "/network-scan"
        )


    target = request.form.get(
        "target",
        ""
    ).strip()


    if not target:

        return redirect(
            "/network-scan"
        )


    results = scan_target(
        target
    )


    scan_id = create_scan(
        user_id=session["user_id"],
        target=target,
        scan_type="Nmap"
    )


    for host in results:

        if "error" in host:

            continue


        for port in host.get(
            "ports",
            []
        ):

            risk = calculate_risk(
                port["port"],
                port.get(
                    "service",
                    ""
                ),
                port.get(
                    "version",
                    ""
                )
            )


            port["severity"] = (
                risk["severity"]
            )

            port["risk_score"] = (
                risk["score"]
            )

            port["recommendation"] = (
                risk["recommendation"]
            )


            save_finding(
                scan_id=scan_id,
                port=port["port"],
                service=port.get(
                    "service",
                    ""
                ),
                version=port.get(
                    "version",
                    ""
                ),
                severity=risk["severity"],
                risk_score=risk["score"],
                recommendation=risk["recommendation"]
            )


    return render_template(
        "scan_results.html",
        target=target,
        results=results,
        scan_id=scan_id,
        name=session["user_name"]
    )


# ============================================================
# WEB SECURITY
# ============================================================

@app.route("/web-security", methods=["GET", "POST"])
def web_security():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    result = None

    target = ""


    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()


        if target:

            result = scan_web(
                target
            )


            scan_id = create_scan(
                user_id=session["user_id"],
                target=target,
                scan_type="Web Security"
            )


            if not result["error"]:

                # ----------------------------------------------------
                # 1. SAVE SECURITY FINDINGS
                # ----------------------------------------------------
                for finding in result.get("findings", []):

                    save_web_finding(
                        scan_id=scan_id,
                        target=target,
                        finding=finding.get("check", "Web Security Check"),
                        severity=finding.get("severity", "Info"),
                        risk_score=finding.get("score", 0),
                        evidence=finding.get("evidence", ""),
                        recommendation=finding.get("recommendation", "Review the detected condition.")
                    )

                # ----------------------------------------------------
                # 2. SAVE ENDPOINT / API DISCOVERY
                # ----------------------------------------------------
                # Discovery is stored as Informational evidence so it
                # appears in Findings and in scan-specific PDF reports,
                # without being treated as a vulnerability.
                for endpoint in result.get("endpoints", []):

                    endpoint_url = endpoint.get("url", "")
                    category = endpoint.get("category", "Endpoint")
                    status_code = endpoint.get("status_code")
                    content_type = endpoint.get("content_type", "")
                    response_time = endpoint.get("response_time", "")
                    confidence = endpoint.get("confidence", "")
                    accessible = endpoint.get("accessible", False)
                    source = endpoint.get("source", "Discovery")

                    evidence_parts = [
                        f"URL: {endpoint_url}",
                        f"Category: {category}",
                        f"Status: {status_code if status_code is not None else 'N/A'}",
                        f"Content-Type: {content_type or 'Unknown'}",
                        f"Response: {response_time if response_time != '' else 'N/A'} s",
                        f"Accessible: {'Yes' if accessible else 'No'}",
                        f"Confidence: {confidence if confidence != '' else 'N/A'}%",
                        f"Source: {source}"
                    ]

                    save_web_finding(
                        scan_id=scan_id,
                        target=target,
                        finding=f"Endpoint Discovered: {category}",
                        severity="Info",
                        risk_score=0,
                        evidence="; ".join(evidence_parts),
                        recommendation="Review the discovered endpoint and confirm that its exposure and access controls are intentional."
                    )

                # ----------------------------------------------------
                # 3. SAVE SUBDOMAIN / ATTACK-SURFACE DISCOVERY
                # ----------------------------------------------------
                for subdomain in result.get("subdomains", []):

                    hostname = subdomain.get("subdomain", "")
                    ip_address = subdomain.get("ip_address", "")
                    record_type = subdomain.get("record_type", "")
                    dns_status = subdomain.get("dns_status", "")
                    http_status = subdomain.get("http_status")
                    https_status = subdomain.get("https_status")
                    service = subdomain.get("service", "")
                    confidence = subdomain.get("confidence", "")
                    wildcard = subdomain.get("wildcard_match", False)
                    status = subdomain.get("status", "Discovered")

                    evidence_parts = [
                        f"Subdomain: {hostname}",
                        f"IP: {ip_address or 'N/A'}",
                        f"DNS: {dns_status or 'Resolved'}",
                        f"Records: {record_type or 'N/A'}",
                        f"HTTP: {http_status if http_status is not None else 'N/A'}",
                        f"HTTPS: {https_status if https_status is not None else 'N/A'}",
                        f"Service: {service or 'Unknown'}",
                        f"Status: {status}",
                        f"Confidence: {confidence if confidence != '' else 'N/A'}%",
                        f"Wildcard DNS match: {'Yes' if wildcard else 'No'}"
                    ]

                    save_web_finding(
                        scan_id=scan_id,
                        target=target,
                        finding="Subdomain Discovered",
                        severity="Info",
                        risk_score=0,
                        evidence="; ".join(evidence_parts),
                        recommendation="Review the discovered subdomain and confirm that its DNS record and exposed services are required and properly secured."
                    )


    return render_template(
        "web_security.html",
        name=session["user_name"],
        target=target,
        result=result
    )


# ============================================================
# TECHNOLOGY FINDER
# ============================================================

@app.route(
    "/technology-finder",
    methods=["GET", "POST"]
)
def technology_finder():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    result = None

    target = ""


    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()


        if target:

            result = find_technologies(
                target
            )


            scan_id = create_scan(
                user_id=session["user_id"],
                target=target,
                scan_type="Technology Finder"
            )


            if not result["error"]:

                for tech in result["technologies"]:

                    technology = tech.get(
                        "technology",
                        ""
                    )

                    version = tech.get(
                        "version",
                        "Unknown"
                    )

                    category = tech.get(
                        "name",
                        ""
                    )

                    risk = tech.get(
                        "risk",
                        "Low"
                    )

                    evidence = tech.get(
                        "evidence",
                        ""
                    )

                    confidence = tech.get(
                        "confidence",
                        70
                    )

                    recommendation = tech.get(
                        "recommendation",
                        ""
                    )


                    save_technology(
                        user_id=session["user_id"],
                        target=target,
                        category=category,
                        technology=technology,
                        version=version,
                        risk=risk,
                        evidence=evidence,
                        confidence=confidence,
                        recommendation=recommendation
                    )


                    save_technology_finding(
                        scan_id=scan_id,
                        target=target,
                        category=category,
                        technology=technology,
                        version=version,
                        risk=risk,
                        evidence=evidence,
                        recommendation=recommendation
                    )


    return render_template(
        "technology_finder.html",
        name=session["user_name"],
        target=target,
        result=result
    )


# ============================================================
# SCAN HISTORY
# ============================================================

# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/scan-history")
def scan_history():

    if "user_name" not in session:
        return redirect("/login")

    # Get only the logged-in user's scan history
    history = get_scan_history(
        session["user_id"]
    )

    # --------------------------------------------------------
    # RESOLVE IP ADDRESS FOR EACH TARGET
    # --------------------------------------------------------

    target_ips = {}

    for scan in history:

        target = str(scan[1]).strip()

        try:

            # If target is already an IP address
            socket.inet_aton(target)

            target_ips[scan[0]] = target

        except socket.error:

            try:

                # Resolve hostname to IPv4
                target_ips[scan[0]] = socket.gethostbyname(
                    target
                )

            except Exception:

                target_ips[scan[0]] = "Not resolved"

    # --------------------------------------------------------
    # RENDER SCAN HISTORY
    # --------------------------------------------------------

    return render_template(
        "scan_history.html",
        name=session["user_name"],
        history=history,
        target_ips=target_ips
    )


# ============================================================
# DELETE SCAN HISTORY RECORD
# ============================================================

@app.route("/delete-scan/<int:scan_id>", methods=["POST"])
def delete_scan_record(scan_id):
    if "user_name" not in session:
        return redirect("/login")

    success = delete_scan(scan_id, session["user_id"])

    if success:
        return redirect("/scan-history?deleted=1")

    return redirect("/scan-history?error=delete")

# ============================================================
# FINDINGS
# ============================================================

@app.route("/findings")
def findings():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    findings_data = get_all_findings(session["user_id"])


    return render_template(
        "findings.html",
        name=session["user_name"],
        findings=findings_data
    )


# ============================================================
# PROFILE
# ============================================================

@app.route("/profile")
def profile():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    return render_template(
        "profile.html",
        name=session["user_name"]
    )


# ============================================================
# SETTINGS
# ============================================================

@app.route("/settings")
def settings():

    if "user_name" not in session:

        return redirect(
            "/login"
        )


    return render_template(
        "settings.html",
        name=session["user_name"]
    )

@app.route("/risk-analysis")
def risk_analysis():
    """
    Risk Analysis supports:
    1. All Scans - combined findings for the logged-in user.
    2. Scan-Specific - findings belonging only to the selected scan_id.
    """

    if "user_name" not in session:
        return redirect("/login")

    # -------------------------------------------------
    # 1. SELECT ANALYSIS SCOPE
    # -------------------------------------------------

    selected_scan_id = request.args.get("scan_id", "").strip()
    selected_scan = None

    if selected_scan_id:
        try:
            selected_scan_id = int(selected_scan_id)
        except ValueError:
            selected_scan_id = ""

    scan_history = get_scan_history(session["user_id"])

    if selected_scan_id:
        for scan in scan_history:
            if int(scan[0]) == int(selected_scan_id):
                selected_scan = scan
                break

        # Ownership check: only the logged-in user's scans are valid.
        if selected_scan is None:
            return redirect("/risk-analysis")

        findings = get_findings_by_scan(
            selected_scan_id,
            session["user_id"]
        )

        analysis_title = (
            f"Scan-Specific Risk Analysis — {selected_scan[1]}"
        )

        analysis_scope = (
            f"Scan #{selected_scan[0]} • "
            f"{selected_scan[1]} • "
            f"{selected_scan[2]}"
        )

        is_scan_specific = True

    else:
        findings = get_all_findings(session["user_id"])

        analysis_title = "Overall Risk Analysis"
        analysis_scope = "All scans for the current user"
        is_scan_specific = False

    # -------------------------------------------------
    # 2. RISK DISTRIBUTION
    # -------------------------------------------------

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    for finding in findings:
        severity = str(finding[7]).lower()

        if severity == "critical":
            critical_count += 1
        elif severity == "high":
            high_count += 1
        elif severity == "medium":
            medium_count += 1
        elif severity == "info":
            info_count += 1
        else:
            low_count += 1

    scored_findings = (
        critical_count
        + high_count
        + medium_count
        + low_count
    )

    total_findings = (
        scored_findings
        + info_count
    )

    # -------------------------------------------------
    # 3. OVERALL RISK SCORE
    # -------------------------------------------------

    if scored_findings > 0:

        weighted_risk = (
            (critical_count * 10)
            + (high_count * 8)
            + (medium_count * 5)
            + (low_count * 2)
        )

        maximum_risk = scored_findings * 10

        risk_percentage = (
            weighted_risk / maximum_risk
        ) * 100

        overall_score = round(
            100 - risk_percentage
        )

        if overall_score < 0:
            overall_score = 0

        if overall_score >= 80:
            risk_level = "Low Risk"
        elif overall_score >= 60:
            risk_level = "Moderate Risk"
        elif overall_score >= 40:
            risk_level = "High Risk"
        else:
            risk_level = "Critical Risk"

    else:
        overall_score = 100
        risk_level = (
            "No Scored Findings"
            if total_findings > 0
            else "No Findings"
        )

    # -------------------------------------------------
    # 4. TOP 5 HIGHEST-RISK FINDINGS
    # -------------------------------------------------

    sorted_findings = sorted(
        findings,
        key=lambda x: int(x[8] or 0),
        reverse=True
    )

    top_findings = sorted_findings[:5]

    # -------------------------------------------------
    # 5. MODULE RISK ANALYSIS
    # -------------------------------------------------

    module_data = {
        "Network": {"total": 0, "risk": 0},
        "Web Security": {"total": 0, "risk": 0},
        "Technology": {"total": 0, "risk": 0}
    }

    for finding in findings:

        source = str(finding[1]).lower()
        risk_score = int(finding[8] or 0)

        if "network" in source or "nmap" in source:
            module = "Network"
        elif "web" in source:
            module = "Web Security"
        elif "technology" in source or "tech" in source:
            module = "Technology"
        else:
            module = None

        if module:
            module_data[module]["total"] += 1
            module_data[module]["risk"] += risk_score

    for module in module_data:

        total = module_data[module]["total"]
        risk = module_data[module]["risk"]

        average_risk = (
            risk / total
            if total > 0
            else 0
        )

        module_data[module]["average"] = round(
            average_risk,
            1
        )

        if average_risk >= 8:
            module_data[module]["level"] = "Critical"
        elif average_risk >= 6:
            module_data[module]["level"] = "High"
        elif average_risk >= 3:
            module_data[module]["level"] = "Medium"
        elif average_risk > 0:
            module_data[module]["level"] = "Low"
        else:
            module_data[module]["level"] = "No Findings"

    # -------------------------------------------------
    # 6. PRIORITY LEVEL
    # -------------------------------------------------

    priority_findings = []

    for finding in findings:

        risk_score = int(finding[8] or 0)

        if risk_score >= 9:
            priority = "Immediate"
        elif risk_score >= 7:
            priority = "High"
        elif risk_score >= 4:
            priority = "Medium"
        else:
            priority = "Low"

        priority_findings.append({
            "finding": finding,
            "priority": priority
        })

    # -------------------------------------------------
    # 7. RECOMMENDATIONS
    # -------------------------------------------------

    recommendations = []

    for finding in sorted_findings:

        recommendation = finding[10]

        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    recommendations = recommendations[:8]

    # -------------------------------------------------
    # 8. RISK PERCENTAGES
    # -------------------------------------------------

    if total_findings > 0:

        critical_percent = (
            critical_count / total_findings
        ) * 100

        high_percent = (
            high_count / total_findings
        ) * 100

        medium_percent = (
            medium_count / total_findings
        ) * 100

        low_percent = (
            low_count / total_findings
        ) * 100

        info_percent = (
            info_count / total_findings
        ) * 100

    else:

        critical_percent = 0
        high_percent = 0
        medium_percent = 0
        low_percent = 0
        info_percent = 0

    # -------------------------------------------------
    # 9. RENDER
    # -------------------------------------------------

    return render_template(
        "risk_analysis.html",

        name=session["user_name"],

        findings=findings,

        # Analysis selector
        scan_history=scan_history,
        selected_scan=selected_scan,
        selected_scan_id=(
            selected_scan_id
            if selected_scan_id
            else ""
        ),
        is_scan_specific=is_scan_specific,
        analysis_title=analysis_title,
        analysis_scope=analysis_scope,

        # Counts
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        total_findings=total_findings,

        # Percentages
        critical_percent=critical_percent,
        high_percent=high_percent,
        medium_percent=medium_percent,
        low_percent=low_percent,
        info_percent=info_percent,

        # Overall risk
        overall_score=overall_score,
        risk_level=risk_level,

        # Existing analysis data
        top_findings=top_findings,
        module_data=module_data,
        priority_findings=priority_findings,
        recommendations=recommendations
    )

# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    if "user_name" not in session:
        return redirect("/login")

    findings = get_all_findings(session["user_id"])

    total_findings = len(findings)

    high_count = 0
    medium_count = 0
    low_count = 0
    critical_count = 0

    # ---------------------------------------------
    # RESOLVE IP ADDRESS FOR EACH FINDING TARGET
    # ---------------------------------------------

    target_ips = {}

    for finding in findings:

        target = str(finding[2]).strip()

        if target in target_ips:
            continue

        try:

            try:
                socket.inet_aton(target)
                target_ips[target] = target

            except socket.error:

                target_ips[target] = socket.gethostbyname(target)

        except Exception:

            target_ips[target] = "Not resolved"

    # ---------------------------------------------
    # SEVERITY COUNTS
    # ---------------------------------------------

    for finding in findings:

        severity = str(finding[7]).lower()

        if severity == "critical":

            critical_count += 1

        elif severity == "high":

            high_count += 1

        elif severity == "medium":

            medium_count += 1

        elif severity == "low":

            low_count += 1

    # ---------------------------------------------
    # REPORT PAGE
    # ---------------------------------------------

    return render_template(

        "reports.html",

        name=session["user_name"],

        findings=findings,

        total_findings=total_findings,

        critical_count=critical_count,

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        target_ips=target_ips
    )

    # ============================================================
# DOWNLOAD PDF REPORT
# ============================================================

@app.route("/reports/pdf")
def reports_pdf():

    if "user_name" not in session:
        return redirect("/login")

    findings = get_all_findings(session["user_id"])

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=10 * mm,
        leftMargin=10 * mm,
        topMargin=10 * mm,
        bottomMargin=10 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0b7189"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0b7189"),
        spaceBefore=10,
        spaceAfter=8
    )

    cell_style = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9
    )

    story = []

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "VectorSpy Security Assessment Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Automated Cybersecurity Assessment Platform",
            subtitle_style
        )
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    total_findings = len(findings)

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    for finding in findings:

        severity = str(finding[7]).lower()

        if severity == "critical":
            critical_count += 1

        elif severity == "high":
            high_count += 1

        elif severity == "medium":
            medium_count += 1

        elif severity == "low":
            low_count += 1
        elif severity == "info":
            info_count += 1

    summary_data = [
        [
            "Total Findings",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info / Discovery"
        ],
        [
            str(total_findings),
            str(critical_count),
            str(high_count),
            str(medium_count),
            str(low_count),
            str(info_count)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            40 * mm,
            30 * mm,
            30 * mm,
            30 * mm,
            30 * mm,
            40 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0b2633")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "BACKGROUND",
                (0, 1),
                (-1, 1),
                colors.HexColor("#f3f8fa")
            ),
            (
                "TEXTCOLOR",
                (0, 1),
                (-1, 1),
                colors.HexColor("#111111")
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTNAME",
                (0, 1),
                (-1, 1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#b8cbd2")
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(summary_table)

    story.append(Spacer(1, 12))

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    table_data = [
        [
            "ID",
            "Source",
            "Target",
            "Finding",
            "Severity",
            "Risk",
            "Evidence",
            "Recommendation"
        ]
    ]

    for finding in findings:

        row = [
            Paragraph(str(finding[0]), cell_style),
            Paragraph(str(finding[1]), cell_style),
            Paragraph(str(finding[2]), cell_style),
            Paragraph(str(finding[3]), cell_style),
            Paragraph(str(finding[7]), cell_style),
            Paragraph(
                f"{finding[8]}/10",
                cell_style
            ),
            Paragraph(str(finding[9]), cell_style),
            Paragraph(str(finding[10]), cell_style)
        ]

        table_data.append(row)

    findings_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            10 * mm,
            25 * mm,
            30 * mm,
            38 * mm,
            22 * mm,
            15 * mm,
            55 * mm,
            60 * mm
        ]
    )

    findings_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0b2633")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, 0),
                7
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#b8cbd2")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f5f9fa")
                ]
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5
            )
        ])
    )

    story.append(findings_table)

    story.append(Spacer(1, 15))

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Generated by VectorSpy • Automated Cybersecurity Assessment Platform",
            subtitle_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                "attachment; filename=VectorSpy_Security_Report.pdf"
        }
    )
# ============================================================
# SCAN SPECIFIC PDF REPORT
# ============================================================

@app.route("/reports/pdf/<int:scan_id>")
def scan_pdf_report(scan_id):

    if "user_name" not in session:
        return redirect("/login")

    findings = get_findings_by_scan(scan_id, session["user_id"])

    if not findings:
        return "No findings found for this scan.", 404

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=10 * mm,
        leftMargin=10 * mm,
        topMargin=10 * mm,
        bottomMargin=10 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ScanReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0b7189"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ScanReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "ScanReportHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0b7189"),
        spaceBefore=10,
        spaceAfter=8
    )

    cell_style = ParagraphStyle(
        "ScanReportCell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9
    )

    story = []

    # --------------------------------------------------------
    # GET SCAN DETAILS
    # --------------------------------------------------------

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, target, scan_type, created_at
        FROM scans
        WHERE id = ?
        AND user_id = ?
        """,
        (scan_id, session["user_id"])
    )

    scan = cursor.fetchone()

    conn.close()

    if not scan:
        return "Scan not found.", 404

    scan_id_value = scan[0]
    target = scan[1]
    scan_type = scan[2]
    created_at = scan[3]

    # Resolve target IP address for the scan-specific PDF.
    try:
        target_text = str(target).strip()
        try:
            socket.inet_aton(target_text)
            target_ip = target_text
        except socket.error:
            target_ip = socket.gethostbyname(target_text)
    except Exception:
        target_ip = "Not resolved"

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "VectorSpy Security Assessment Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Scan-Specific Security Assessment",
            subtitle_style
        )
    )

    # --------------------------------------------------------
    # SCAN INFORMATION
    # --------------------------------------------------------

    scan_info = [
        ["Scan ID", str(scan_id_value)],
        ["Target", str(target)],
        ["IP Address", str(target_ip)],
        ["Scan Type", str(scan_type)],
        ["Date & Time", str(created_at)],
    ]

    scan_table = Table(
        scan_info,
        colWidths=[
            35 * mm,
            70 * mm
        ]
    )

    scan_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#0b2633")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.white
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                colors.HexColor("#f3f8fa")
            ),
            (
                "TEXTCOLOR",
                (1, 0),
                (1, -1),
                colors.HexColor("#111111")
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#b8cbd2")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(scan_table)

    story.append(Spacer(1, 15))

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    total = len(findings)

    critical = 0
    high = 0
    medium = 0
    low = 0

    for finding in findings:

        severity = str(finding[7]).lower()

        if severity == "critical":
            critical += 1

        elif severity == "high":
            high += 1

        elif severity == "medium":
            medium += 1

        elif severity == "low":
            low += 1

    summary_data = [
        [
            "Total Findings",
            "Critical",
            "High",
            "Medium",
            "Low"
        ],
        [
            str(total),
            str(critical),
            str(high),
            str(medium),
            str(low)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            45 * mm,
            35 * mm,
            35 * mm,
            35 * mm,
            35 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0b2633")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "BACKGROUND",
                (0, 1),
                (-1, 1),
                colors.HexColor("#f3f8fa")
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#b8cbd2")
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(summary_table)

    story.append(Spacer(1, 15))

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    table_data = [
        [
            "ID",
            "Source",
            "Finding",
            "Severity",
            "Risk",
            "Evidence",
            "Recommendation"
        ]
    ]

    for finding in findings:

        row = [
            Paragraph(str(finding[0]), cell_style),

            Paragraph(
                str(finding[1]),
                cell_style
            ),

            Paragraph(
                str(finding[3]),
                cell_style
            ),

            Paragraph(
                str(finding[7]),
                cell_style
            ),

            Paragraph(
                f"{finding[8]}/10",
                cell_style
            ),

            Paragraph(
                str(finding[9]),
                cell_style
            ),

            Paragraph(
                str(finding[10]),
                cell_style
            )
        ]

        table_data.append(row)

    findings_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            10 * mm,
            25 * mm,
            40 * mm,
            22 * mm,
            15 * mm,
            60 * mm,
            65 * mm
        ]
    )

    findings_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0b2633")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, 0),
                7
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#b8cbd2")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f5f9fa")
                ]
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5
            )
        ])
    )

    story.append(findings_table)

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Generated by VectorSpy • Automated Cybersecurity Assessment Platform",
            subtitle_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                f"attachment; filename=VectorSpy_Scan_{scan_id}_Report.pdf"
        }
    )
# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        "/welcome"
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )