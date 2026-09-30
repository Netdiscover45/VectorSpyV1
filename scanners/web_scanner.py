"""VectorSpy - Web Security Scanner
Authorized passive web security assessment module.

This module performs non-destructive GET/OPTIONS based checks and limited
same-origin endpoint discovery. It is not a full vulnerability scanner.
Only scan systems you own or are explicitly authorized to assess.
"""

import re
import time
import warnings
import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

REQUEST_TIMEOUT = 10
ENDPOINT_TIMEOUT = 5
MAX_ENDPOINTS = 45
MAX_RESPONSE_SIZE = 2 * 1024 * 1024
USER_AGENT = "VectorSpy-WebSecurityScanner/3.0 (Authorized Security Assessment)"

COMMON_ENDPOINTS = [
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/rest", "/rest/", "/graphql", "/graphql/", "/swagger", "/swagger/",
    "/swagger-ui", "/swagger-ui/", "/swagger-ui.html", "/openapi.json",
    "/openapi.yaml", "/api-docs", "/api/docs", "/docs", "/docs/",
    "/redoc", "/redoc/", "/health", "/health/", "/healthz", "/ready",
    "/readiness", "/status", "/metrics", "/login", "/signin", "/admin",
    "/admin/", "/dashboard", "/robots.txt", "/sitemap.xml",
]

SENSITIVE_WORDS = (
    "/admin", "/dashboard", "/login", "/signin", "/account",
    "/manage", "/management", "/internal", "/private"
)


def _normalize_url(target):
    target = str(target or "").strip()
    if not target:
        return "", "Target URL is required."
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.hostname:
        return "", "Invalid target URL."
    return target, ""


def _clean(value):
    return "" if value is None else str(value).strip()


def _header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return _clean(value)
    return ""


def _same_origin(base_url, candidate_url):
    try:
        base = urlparse(base_url)
        candidate = urlparse(candidate_url)
        base_port = base.port or (443 if base.scheme == "https" else 80)
        candidate_port = candidate.port or (443 if candidate.scheme == "https" else 80)
        return (
            base.scheme.lower() == candidate.scheme.lower()
            and (base.hostname or "").lower() == (candidate.hostname or "").lower()
            and base_port == candidate_port
        )
    except Exception:
        return False


def _normalize_endpoint(base_url, href):
    href = _clean(href)
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return ""
    absolute = urljoin(base_url, href)
    absolute, _ = urldefrag(absolute)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    return absolute


def _finding(check, finding, severity, score, confidence, evidence, recommendation):
    return {
        "check": check,
        "finding": finding,
        "severity": severity,
        "score": score,
        "risk_score": score,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _is_html(response):
    return "text/html" in _header(response.headers, "Content-Type").lower()


def _is_json(response):
    content_type = _header(response.headers, "Content-Type").lower()
    return "json" in content_type or "+json" in content_type


def _check_security_headers(response, findings):
    # Browser-oriented headers are evaluated primarily on HTML/document responses.
    if not _is_html(response):
        return

    csp = _header(response.headers, "Content-Security-Policy")
    if not csp:
        findings.append(_finding(
            "Content Security Policy", "Missing Content-Security-Policy", "Medium", 5, 95,
            "HTML response does not contain a Content-Security-Policy header.",
            "Define a suitable Content-Security-Policy for browser-rendered content."
        ))
    else:
        low = csp.lower()
        if "unsafe-inline" in low:
            findings.append(_finding(
                "Content Security Policy", "CSP allows unsafe-inline", "Medium", 5, 90,
                f"Content-Security-Policy: {csp}",
                "Avoid unsafe-inline where practical; prefer nonces or hashes."
            ))
        if "unsafe-eval" in low:
            findings.append(_finding(
                "Content Security Policy", "CSP allows unsafe-eval", "Medium", 5, 90,
                f"Content-Security-Policy: {csp}",
                "Avoid unsafe-eval where practical."
            ))

    x_frame = _header(response.headers, "X-Frame-Options")
    frame_ancestors = "frame-ancestors" in csp.lower() if csp else False
    if not x_frame and not frame_ancestors:
        findings.append(_finding(
            "Clickjacking Protection", "Missing clickjacking protection", "Medium", 5, 95,
            "Neither X-Frame-Options nor CSP frame-ancestors was observed on the HTML response.",
            "Configure X-Frame-Options or an appropriate CSP frame-ancestors policy."
        ))
    elif x_frame and x_frame.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(_finding(
            "Clickjacking Protection", "Unusual X-Frame-Options configuration", "Low", 2, 90,
            f"X-Frame-Options: {x_frame}",
            "Use DENY or SAMEORIGIN when appropriate."
        ))

    xcto = _header(response.headers, "X-Content-Type-Options")
    if not xcto:
        findings.append(_finding(
            "MIME Sniffing Protection", "Missing X-Content-Type-Options", "Low", 2, 95,
            "X-Content-Type-Options header not present on the HTML response.",
            "Set X-Content-Type-Options to nosniff."
        ))
    elif xcto.lower() != "nosniff":
        findings.append(_finding(
            "MIME Sniffing Protection", "Weak X-Content-Type-Options configuration", "Low", 2, 95,
            f"X-Content-Type-Options: {xcto}", "Use the value nosniff."
        ))

    referrer = _header(response.headers, "Referrer-Policy")
    if not referrer:
        findings.append(_finding(
            "Referrer Policy", "Missing Referrer-Policy", "Low", 2, 90,
            "Referrer-Policy header not present on the HTML response.",
            "Configure an appropriate Referrer-Policy."
        ))

    permissions = _header(response.headers, "Permissions-Policy")
    if not permissions:
        findings.append(_finding(
            "Permissions Policy", "Missing Permissions-Policy", "Info", 0, 80,
            "Permissions-Policy header not present.",
            "Consider restricting browser capabilities that the application does not need."
        ))

    coop = _header(response.headers, "Cross-Origin-Opener-Policy")
    if not coop:
        findings.append(_finding(
            "Cross-Origin Isolation", "Cross-Origin-Opener-Policy not observed", "Info", 0, 75,
            "Cross-Origin-Opener-Policy header not present.",
            "Consider COOP when cross-origin isolation is required by the application."
        ))

    corp = _header(response.headers, "Cross-Origin-Resource-Policy")
    if not corp:
        findings.append(_finding(
            "Cross-Origin Resource Policy", "Cross-Origin-Resource-Policy not observed", "Info", 0, 75,
            "Cross-Origin-Resource-Policy header not present.",
            "Consider CORP where cross-origin resource control is required."
        ))

    if response.url.lower().startswith("https://"):
        hsts = _header(response.headers, "Strict-Transport-Security")
        if not hsts:
            findings.append(_finding(
                "Transport Security", "Missing Strict-Transport-Security", "Medium", 5, 95,
                "HTTPS HTML response did not include HSTS.",
                "Configure Strict-Transport-Security after verifying the site is consistently HTTPS."
            ))
        elif "max-age=" not in hsts.lower():
            findings.append(_finding(
                "Transport Security", "Malformed HSTS configuration", "Medium", 5, 95,
                f"Strict-Transport-Security: {hsts}",
                "Configure HSTS with a valid max-age directive."
            ))

    acao = _header(response.headers, "Access-Control-Allow-Origin")
    if acao == "*":
        findings.append(_finding(
            "CORS Configuration", "Wildcard Access-Control-Allow-Origin detected", "Low", 2, 90,
            "Access-Control-Allow-Origin: *", 
            "Use specific trusted origins when cross-origin access is required, especially for sensitive APIs."
        ))


def _check_information_disclosure(response, findings):
    server = _header(response.headers, "Server")
    if server:
        findings.append(_finding(
            "Server Disclosure", "Server header discloses technology information", "Low", 2, 95,
            f"Server: {server}", "Minimize unnecessary server/product disclosure where practical."
        ))
    powered_by = _header(response.headers, "X-Powered-By")
    if powered_by:
        findings.append(_finding(
            "Technology Disclosure", "X-Powered-By exposes technology information", "Low", 2, 95,
            f"X-Powered-By: {powered_by}", "Remove unnecessary technology disclosure."
        ))


def _analyze_cookies(response, findings):
    try:
        cookies = response.raw.headers.get_all("Set-Cookie")
    except Exception:
        cookies = None
    if not cookies:
        single = response.headers.get("Set-Cookie")
        cookies = [single] if single else []

    for cookie in cookies:
        cookie = _clean(cookie)
        if not cookie:
            continue
        lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip() or "cookie"
        if response.url.lower().startswith("https://") and "secure" not in lower:
            findings.append(_finding(
                "Cookie Security", "Cookie missing Secure attribute", "Medium", 5, 90,
                f"{cookie_name}: Secure attribute missing.",
                "Set Secure on cookies that should only travel over HTTPS."
            ))
        if "httponly" not in lower:
            findings.append(_finding(
                "Cookie Security", "Cookie missing HttpOnly attribute", "Medium", 5, 85,
                f"{cookie_name}: HttpOnly attribute missing.",
                "Set HttpOnly where client-side JavaScript access is unnecessary."
            ))
        if "samesite=" not in lower:
            findings.append(_finding(
                "Cookie Security", "Cookie missing SameSite attribute", "Low", 2, 85,
                f"{cookie_name}: SameSite attribute missing.",
                "Configure an appropriate SameSite policy."
            ))


def _check_cache_control(response, findings):
    cache = _header(response.headers, "Cache-Control")
    if cache:
        return
    content_type = _header(response.headers, "Content-Type").lower()
    if "text/html" in content_type:
        findings.append(_finding(
            "Cache Control", "Cache-Control header not present", "Low", 2, 80,
            "HTML response does not include Cache-Control.",
            "Define appropriate caching rules, particularly for authenticated or sensitive pages."
        ))


def _check_content_type(response, findings):
    content_type = _header(response.headers, "Content-Type")
    if not content_type:
        findings.append(_finding(
            "Content Type", "Content-Type header not present", "Low", 2, 90,
            "Content-Type header not present.", "Return the correct Content-Type."
        ))


def _check_options(session, url, findings):
    try:
        response = session.options(url, timeout=ENDPOINT_TIMEOUT, allow_redirects=True, verify=False)
        allow = _header(response.headers, "Allow")
        if not allow:
            return
        methods = {item.strip().upper() for item in allow.split(",")}
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in methods]
        if risky:
            findings.append(_finding(
                "HTTP Methods", "Potentially sensitive HTTP methods advertised", "Medium", 5, 90,
                f"Allow: {allow}", "Disable unnecessary HTTP methods."
            ))
    except requests.RequestException:
        pass


def _check_response(response, response_time, findings):
    if 500 <= response.status_code <= 599:
        findings.append(_finding(
            "HTTP Response", "Server returned a 5xx response", "Medium", 5, 95,
            f"HTTP status code: {response.status_code}",
            "Investigate server-side errors and avoid exposing internal details."
        ))
    if response_time > 5:
        findings.append(_finding(
            "Response Performance", "Slow HTTP response detected", "Low", 2, 85,
            f"Response time: {response_time:.2f} seconds",
            "Review server processing and application performance."
        ))


def _check_https_redirect(original_target, response, findings):
    parsed = urlparse(original_target)
    if parsed.scheme.lower() != "http":
        return
    if not response.url.lower().startswith("https://"):
        findings.append(_finding(
            "HTTPS Redirect", "HTTP request did not redirect to HTTPS", "Medium", 5, 95,
            f"Final URL: {response.url}", "Redirect HTTP traffic to HTTPS."
        ))


def _discover_html_endpoints(response, base_url):
    discovered = []
    if not _is_html(response):
        return discovered
    try:
        html = response.text[:MAX_RESPONSE_SIZE]
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            endpoint = _normalize_endpoint(base_url, tag.get("href"))
            if endpoint and _same_origin(base_url, endpoint) and endpoint not in discovered:
                discovered.append(endpoint)
        for tag in soup.find_all("form", action=True):
            endpoint = _normalize_endpoint(base_url, tag.get("action"))
            if endpoint and _same_origin(base_url, endpoint) and endpoint not in discovered:
                discovered.append(endpoint)
        for tag in soup.find_all("script", src=True):
            endpoint = _normalize_endpoint(base_url, tag.get("src"))
            if endpoint and _same_origin(base_url, endpoint) and endpoint not in discovered:
                discovered.append(endpoint)
    except Exception:
        pass
    return discovered


def _discover_api_patterns(response, base_url):
    discovered = []
    try:
        body = response.text[:MAX_RESPONSE_SIZE]
        patterns = [
            r'["\'](\/api(?:\/v\d+)?(?:\/[^"\']*)?)["\']',
            r'["\'](\/graphql(?:\/[^"\']*)?)["\']',
            r'["\'](\/rest(?:\/[^"\']*)?)["\']',
            r'["\'](\/v\d+\/[^"\']+)["\']',
        ]
        for pattern in patterns:
            for item in re.findall(pattern, body, flags=re.I):
                endpoint = _normalize_endpoint(base_url, item)
                if endpoint and _same_origin(base_url, endpoint) and endpoint not in discovered:
                    discovered.append(endpoint)
    except Exception:
        pass
    return discovered


def _discover_metadata(response, base_url):
    """Return extra metadata endpoints found from robots/sitemap references."""
    discovered = []
    try:
        if response.url.lower().endswith("robots.txt"):
            text = response.text[:MAX_RESPONSE_SIZE]
            for line in text.splitlines():
                if line.lower().startswith("sitemap:"):
                    endpoint = _normalize_endpoint(base_url, line.split(":", 1)[1].strip())
                    if endpoint and _same_origin(base_url, endpoint):
                        discovered.append(endpoint)
    except Exception:
        pass
    return discovered


def _common_endpoints(base_url):
    return [urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) for path in COMMON_ENDPOINTS]


def _classify_endpoint(endpoint, source):
    path = urlparse(endpoint).path.lower().rstrip("/") or "/"
    if any(x in path for x in ("swagger", "openapi", "redoc", "/api-docs", "/docs")):
        return "API Documentation", 90
    if "/graphql" in path:
        return "GraphQL", 90
    if "/api" in path or "/rest" in path or re.search(r"/v\d+(?:/|$)", path):
        return "Potential API Endpoint", 85
    if path.endswith(("/robots.txt", "/sitemap.xml")):
        return "Metadata Endpoint", 95
    if any(word in path for word in SENSITIVE_WORDS):
        return "Potential Administrative/Auth Endpoint", 80
    if source == "HTML form":
        return "Form Endpoint", 80
    if source == "JavaScript/HTML pattern":
        return "Discovered Endpoint", 70
    if path.endswith((".js", ".mjs")):
        return "JavaScript Resource", 95
    return "Endpoint", 70


def _test_endpoint(session, endpoint, source="Common Endpoint"):
    started = time.perf_counter()
    result = {
        "url": endpoint,
        "final_url": "",
        "status_code": None,
        "content_type": "",
        "content_length": "",
        "response_time": 0,
        "type": "Endpoint",
        "category": "Endpoint",
        "source": source,
        "confidence": 70,
        "tls_verified": False,
        "accessible": False,
        "body_sample": "",
        "error": "",
    }
    try:
        # Endpoint probing intentionally uses verify=False after the main target
        # has been reached. This prevents a local CA-store problem from stopping
        # the discovery phase. TLS validation is therefore NOT claimed here.
        response = session.get(
            endpoint,
            timeout=(3.05, ENDPOINT_TIMEOUT),
            allow_redirects=True,
            verify=False,
            stream=True,
        )
        elapsed = time.perf_counter() - started
        result.update({
            "final_url": response.url,
            "status_code": response.status_code,
            "content_type": _header(response.headers, "Content-Type"),
            "content_length": _header(response.headers, "Content-Length"),
            "response_time": round(elapsed, 3),
            "accessible": True,
        })
        category, confidence = _classify_endpoint(endpoint, source)
        result["category"] = category
        result["type"] = category
        result["confidence"] = confidence
        try:
            body_sample = response.raw.read(4096, decode_content=True)
            result["body_sample"] = body_sample.decode("utf-8", errors="ignore")[:500]
        except Exception:
            pass
        finally:
            response.close()
        return result
    except requests.exceptions.SSLError as exc:
        result.update({"type": "TLS Error", "category": "TLS Error", "error": str(exc)})
    except requests.exceptions.Timeout as exc:
        result.update({"type": "Timeout", "category": "Timeout", "error": str(exc)})
    except requests.exceptions.ConnectionError as exc:
        result.update({"type": "Connection Error", "category": "Connection Error", "error": str(exc)})
    except requests.exceptions.RequestException as exc:
        result.update({"type": "Request Error", "category": "Request Error", "error": str(exc)})
    except Exception as exc:
        result.update({"type": "Error", "category": "Error", "error": str(exc)})
    return result


def _analyze_endpoints(endpoint_results, findings):
    for item in endpoint_results:
        status = item.get("status_code")
        if not status:
            continue
        endpoint = item.get("url", "")
        category = item.get("category", "Endpoint")
        content_type = item.get("content_type") or "Unknown"
        evidence = f"{endpoint} | HTTP {status} | Content-Type: {content_type}"

        if category in ("Potential API Endpoint", "GraphQL"):
            findings.append(_finding(
                "API Discovery", "Potential API endpoint discovered", "Info", 0, item.get("confidence", 85),
                evidence, "Review authentication, authorization and unnecessary public exposure."
            ))
        elif category == "API Documentation":
            findings.append(_finding(
                "API Documentation", "API documentation endpoint discovered", "Low", 2, item.get("confidence", 90),
                evidence, "Ensure API documentation does not expose sensitive internal information in production."
            ))
        elif category == "Potential Administrative/Auth Endpoint":
            findings.append(_finding(
                "Endpoint Discovery", "Administrative or authentication endpoint discovered", "Info", 0, item.get("confidence", 80),
                evidence, "Verify authentication and authorization controls are properly enforced."
            ))
            if status == 200 and urlparse(endpoint).path.rstrip("/").lower() in ("/admin", "/dashboard"):
                findings.append(_finding(
                    "Endpoint Exposure", "Administrative endpoint returned HTTP 200", "Medium", 5, 80,
                    evidence, "Verify authentication and authorization before exposing administrative functionality."
                ))
        elif category == "Metadata Endpoint":
            findings.append(_finding(
                "Metadata Discovery", "Public metadata endpoint discovered", "Info", 0, 90,
                evidence, "Review robots.txt or sitemap.xml for unnecessary disclosure of sensitive paths."
            ))


def _summary(findings, endpoint_results):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        key = str(item.get("severity", "Info")).lower()
        if key in counts:
            counts[key] += 1
    if counts["critical"]:
        risk = "Critical"
    elif counts["high"]:
        risk = "High"
    elif counts["medium"]:
        risk = "Medium"
    elif counts["low"]:
        risk = "Low"
    else:
        risk = "Informational"
    api_count = sum(1 for x in endpoint_results if x.get("category") in ("Potential API Endpoint", "GraphQL", "API Documentation"))
    return {
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "discovered_endpoints": len(endpoint_results),
        "api_endpoints": api_count,
        "accessible_endpoints": sum(1 for x in endpoint_results if x.get("accessible")),
        "risk_level": risk,
    }


def _failed_result(target, status, error, finding=None):
    findings = [finding] if finding else []
    return {
        "success": False,
        "status": status,
        "status_code": None,
        "target": target,
        "final_url": target,
        "response_time": 0,
        "findings": findings,
        "endpoints": [],
        "subdomains": [],
        "subdomain_discovery": {},
        "error": error,
        "summary": _summary(findings, []),
    }



def _resolve_hostname(hostname, timeout=2.5):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        addresses, record_types = [], []
        for family, _, _, _, sockaddr in infos:
            if not sockaddr:
                continue
            address = sockaddr[0]
            if address not in addresses:
                addresses.append(address)
            if family == socket.AF_INET:
                record_types.append("A")
            elif family == socket.AF_INET6:
                record_types.append("AAAA")
        return {"addresses": list(dict.fromkeys(addresses)), "record_types": list(dict.fromkeys(record_types))}
    except (socket.gaierror, socket.timeout, TimeoutError):
        return {"addresses": [], "record_types": []}
    except Exception:
        return {"addresses": [], "record_types": []}
    finally:
        socket.setdefaulttimeout(old_timeout)


def _detect_wildcard_dns(domain):
    label = "vsp-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    hostname = f"{label}.{domain}"
    resolution = _resolve_hostname(hostname)
    return {"enabled": bool(resolution["addresses"]), "addresses": resolution["addresses"]}


def _probe_subdomain_http(hostname):
    result = {
        "http_status": None,
        "http_status_reason": "",
        "https_status": None,
        "https_status_reason": "",
        "final_url": "",
        "response_time": None,
        "service": "DNS only",
        "tls_verified": None,
    }
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            started = time.perf_counter()
            response = requests.head(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=4,
                allow_redirects=True,
                verify=True,
            )
            if response.status_code in (405, 501):
                response = requests.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=4,
                    allow_redirects=True,
                    verify=True,
                    stream=True,
                )
            elapsed = round(time.perf_counter() - started, 3)
            result["final_url"] = str(response.url or url)
            result["response_time"] = elapsed
            if scheme == "https":
                result["https_status"] = response.status_code
                result["https_status_reason"] = response.reason or ""
                result["tls_verified"] = True
                result["service"] = "HTTPS"
            else:
                result["http_status"] = response.status_code
                result["http_status_reason"] = response.reason or ""
                if result["service"] == "DNS only":
                    result["service"] = "HTTP"
            try:
                response.close()
            except Exception:
                pass
            return result
        except requests.exceptions.SSLError:
            if scheme == "https":
                result["tls_verified"] = False
        except requests.exceptions.RequestException:
            continue
    return result


def _check_one_subdomain(prefix, domain, wildcard):
    hostname = f"{prefix}.{domain}"
    dns = _resolve_hostname(hostname)
    if not dns["addresses"]:
        return None

    wildcard_match = wildcard["enabled"] and bool(
        set(dns["addresses"]).intersection(wildcard["addresses"])
    )

    item = {
        "subdomain": hostname,
        "ip_address": ", ".join(dns["addresses"][:5]),
        "record_type": ", ".join(dns["record_types"]),
        "status": "Wildcard DNS" if wildcard_match else "DNS Active",
        "http_status": None,
        "http_status_reason": "",
        "https_status": None,
        "https_status_reason": "",
        "final_url": "",
        "response_time": None,
        "service": "DNS only",
        "tls_verified": None,
        "confidence": 45 if wildcard_match else 88,
        "source": "DNS resolution",
        "evidence": f"DNS resolved to {', '.join(dns['addresses'][:5])}.",
    }

    if wildcard_match:
        item["source"] = "DNS + wildcard comparison"
        item["evidence"] = (
            "Hostname resolved, but its address matches the detected wildcard DNS response."
        )

    http = _probe_subdomain_http(hostname)
    item.update(http)

    if http["https_status"] is not None:
        item["status"] = "Active HTTPS"
        item["confidence"] = min(99, item["confidence"] + 8)
        item["evidence"] += f" HTTPS response: {http['https_status']} {http.get('https_status_reason', '')}."
    elif http["http_status"] is not None:
        item["status"] = "Active HTTP"
        item["confidence"] = min(98, item["confidence"] + 5)
        item["evidence"] += f" HTTP response: {http['http_status']} {http.get('http_status_reason', '')}."

    return item


def _discover_subdomains(domain):
    """Bounded common-name DNS discovery integrated into Web Security."""
    common = [
        "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "api",
        "app", "portal", "admin", "login", "auth", "dev", "test",
        "staging", "demo", "beta", "support", "help", "blog", "shop",
        "store", "cdn", "static", "assets", "media", "docs", "status",
    ]
    wildcard = _detect_wildcard_dns(domain)
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_one_subdomain, prefix, domain, wildcard) for prefix in common]
        for future in as_completed(futures):
            try:
                item = future.result()
                if item:
                    results.append(item)
            except Exception:
                continue
    results.sort(key=lambda x: x.get("subdomain", ""))
    return {
        "subdomains": results,
        "checked": len(common),
        "wildcard_dns": wildcard["enabled"],
        "wildcard_addresses": wildcard["addresses"],
        "dns_active": len(results),
        "http_active": sum(1 for x in results if x.get("http_status") is not None),
        "https_active": sum(1 for x in results if x.get("https_status") is not None),
    }


def _domain_from_url(url):
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""

def scan_web(target):
    target_url, error = _normalize_url(target)
    if error:
        return _failed_result(target, "Failed", error)

    findings = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    })

    started = time.perf_counter()
    try:
        response = session.get(
            target_url,
            timeout=(3.05, REQUEST_TIMEOUT),
            allow_redirects=True,
            verify=True,
        )
        response_time = time.perf_counter() - started
    except requests.exceptions.SSLError as exc:
        finding = _finding(
            "TLS", "TLS certificate validation failed", "High", 8, 95,
            str(exc), "Install a valid trusted TLS certificate."
        )
        return _failed_result(target_url, "TLS Error", str(exc), finding)
    except requests.exceptions.Timeout:
        return _failed_result(target_url, "Timeout", f"Target did not respond within {REQUEST_TIMEOUT} seconds.")
    except requests.exceptions.ConnectionError as exc:
        return _failed_result(target_url, "Connection Error", f"Unable to connect to target: {exc}")
    except requests.exceptions.RequestException as exc:
        return _failed_result(target_url, "Request Error", str(exc))

    _check_security_headers(response, findings)
    _check_information_disclosure(response, findings)
    _check_cache_control(response, findings)
    _check_content_type(response, findings)
    _analyze_cookies(response, findings)
    _check_response(response, response_time, findings)
    _check_https_redirect(target_url, response, findings)
    _check_options(session, response.url, findings)

    discovered = []
    discovered_sources = {}

    for endpoint in _discover_html_endpoints(response, response.url):
        discovered.append(endpoint)
        discovered_sources.setdefault(endpoint, "HTML link/form/script")

    for endpoint in _discover_api_patterns(response, response.url):
        discovered.append(endpoint)
        discovered_sources.setdefault(endpoint, "JavaScript/HTML pattern")

    for endpoint in _common_endpoints(response.url):
        discovered.append(endpoint)
        discovered_sources.setdefault(endpoint, "Common Endpoint")

    # Test only same-origin endpoints and cap the number of requests.
    unique_endpoints = []
    for endpoint in discovered:
        if endpoint not in unique_endpoints and _same_origin(response.url, endpoint):
            unique_endpoints.append(endpoint)
        if len(unique_endpoints) >= MAX_ENDPOINTS:
            break

    endpoint_results = []
    for endpoint in unique_endpoints:
        endpoint_results.append(_test_endpoint(
            session, endpoint, discovered_sources.get(endpoint, "Discovery")
        ))

    # If robots.txt was reachable, discover sitemap references without crawling it broadly.
    for item in endpoint_results:
        if item.get("url", "").lower().endswith("/robots.txt") and item.get("status_code") == 200:
            for endpoint in _discover_metadata(response, response.url):
                if endpoint not in [x.get("url") for x in endpoint_results] and len(endpoint_results) < MAX_ENDPOINTS:
                    endpoint_results.append(_test_endpoint(session, endpoint, "robots.txt"))

    _analyze_endpoints(endpoint_results, findings)

    # --------------------------------------------------------
    # SUBDOMAIN / WEB ATTACK-SURFACE DISCOVERY
    # --------------------------------------------------------
    domain = _domain_from_url(response.url)
    subdomain_result = _discover_subdomains(domain) if domain else {
        "subdomains": [], "checked": 0, "wildcard_dns": False,
        "wildcard_addresses": [], "dns_active": 0, "http_active": 0, "https_active": 0
    }

    summary = _summary(findings, endpoint_results)
    summary.update({
        "discovered_subdomains": len(subdomain_result["subdomains"]),
        "dns_active_subdomains": subdomain_result["dns_active"],
        "http_active_subdomains": subdomain_result["http_active"],
        "https_active_subdomains": subdomain_result["https_active"],
        "subdomain_checks": subdomain_result["checked"],
    })

    return {
        "success": True,
        "status": "Completed",
        "status_code": response.status_code,
        "target": target_url,
        "final_url": response.url,
        "response_time": round(response_time, 3),
        "findings": findings,
        "endpoints": endpoint_results,
        "subdomains": subdomain_result["subdomains"],
        "subdomain_discovery": subdomain_result,
        "error": "",
        "summary": summary,
    }


def scan_target(target):
    """Compatibility wrapper for older VectorSpy routes."""
    return scan_web(target)
