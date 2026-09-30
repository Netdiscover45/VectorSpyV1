import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

try:
    from wappalyzer import Wappalyzer
except ImportError:
    Wappalyzer = None

USER_AGENT = "VectorSpy-Advanced-Technology-Finder/2.0"
REQUEST_TIMEOUT = (8, 15)
MAX_HTML_SIZE = 3 * 1024 * 1024
WAPPALYZER_TIMEOUT = 30


def extract_version(patterns, text):
    if not text:
        return "Unknown"
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                return match.group(1)
            except IndexError:
                return "Unknown"
    return "Unknown"


def clean_text(value, limit=500):
    value = re.sub(r"\s+", " ", str(value or "")).strip()
    return value[:limit]


def normalize_target(target):
    target = str(target or "").strip()
    if target and not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target


def safe_url(url, base_url):
    try:
        absolute = urljoin(base_url, url)
        parsed = urlparse(absolute)
        return absolute if parsed.scheme in ("http", "https") else ""
    except Exception:
        return ""


def add_technology(technologies, technology, category, version,
                   evidence, risk, recommendation, confidence=70):
    technology = clean_text(technology, 120)
    version = clean_text(version, 80) or "Unknown"
    evidence = clean_text(evidence, 700)
    confidence = max(0, min(100, int(confidence)))

    if not technology:
        return

    for item in technologies:
        if item["technology"].lower() == technology.lower():
            if confidence > item.get("confidence", 0):
                item["confidence"] = confidence
            if version != "Unknown" and item.get("version") in ("Unknown", "", None):
                item["version"] = version
            if evidence and evidence not in item.get("evidence", ""):
                old = item.get("evidence", "")
                item["evidence"] = f"{old} | {evidence}" if old else evidence
            return

    technologies.append({
        "name": category,
        "technology": technology,
        "version": version,
        "risk": risk,
        "evidence": evidence,
        "confidence": confidence,
        "recommendation": recommendation
    })


def _version_tuple(version):
    """Return a comparable numeric version tuple."""
    if not version or str(version).strip().lower() in {"unknown", "not exposed", "n/a"}:
        return None

    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(version))
    if not match:
        return None

    return tuple(int(part or 0) for part in match.groups())


def technology_risk(technology, version=""):
    """Assign context-aware risk; detection alone is not a vulnerability."""
    tech = technology.lower().strip()
    ver = _version_tuple(version)

    if tech in {"telnet", "ftp"}:
        return (
            "High",
            "Review whether this service is required. Prefer encrypted alternatives and restrict unnecessary exposure."
        )

    if tech == "php" and ver:
        major, minor, _ = ver
        if major == 8 and minor <= 1:
            return (
                "High",
                "Upgrade to a currently supported PHP branch and avoid exposing the PHP version in HTTP headers."
            )
        if major == 8 and minor == 2:
            return (
                "Medium",
                "Plan migration to a newer supported PHP branch and avoid unnecessary version disclosure."
            )
        return (
            "Low",
            "Keep PHP patched and avoid unnecessary version disclosure."
        )

    if tech == "php":
        return (
            "Info",
            "PHP was detected. Confirm the deployed version and keep the runtime on a supported branch."
        )

    if tech == "jquery":
        if ver and ver[0] <= 2:
            return (
                "Medium",
                "Review the legacy jQuery version and plan an upgrade after compatibility testing."
            )
        if ver and ver[0] == 3:
            return (
                "Low",
                "Keep jQuery patched and review third-party dependency usage."
            )
        return (
            "Info",
            "jQuery was detected. Confirm the exact version and review dependency maintenance."
        )

    if tech in {
        "wordpress", "drupal", "joomla", "angular", "react", "vue.js",
        "laravel", "apache", "nginx", "microsoft iis", "litespeed",
        "caddy", "bootstrap", "tailwind css", "font awesome",
        "google analytics", "google tag manager", "cloudflare",
        "amazon cloudfront", "fastly", "shopify", "elementor"
    }:
        return (
            "Info",
            "Technology fingerprint detected. Detection alone does not prove a vulnerability; keep the component maintained and verify its version."
        )

    return (
        "Info",
        "Technology detected. Review its version, maintenance status and security configuration."
    )

def extract_resources(soup, base_url):
    scripts, stylesheets, links = [], [], []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            url = safe_url(src, base_url)
            if url:
                scripts.append(url)

    for tag in soup.find_all("link"):
        href = tag.get("href")
        if not href:
            continue
        url = safe_url(href, base_url)
        if not url:
            continue
        rel = " ".join(tag.get("rel", [])).lower()
        if "stylesheet" in rel:
            stylesheets.append(url)
        links.append(url)

    return sorted(set(scripts)), sorted(set(stylesheets)), sorted(set(links))



def wappalyzer_category(technology):
    """Map common Wappalyzer detections to VectorSpy's UI categories."""
    tech = str(technology or "").lower()

    if any(x in tech for x in ("wordpress", "drupal", "joomla", "magento", "shopify")):
        return "CMS / E-commerce"
    if any(x in tech for x in ("react", "vue", "angular", "svelte", "next.js", "nuxt")):
        return "JavaScript / Web Framework"
    if any(x in tech for x in ("jquery", "bootstrap", "tailwind", "font awesome")):
        return "JavaScript / UI Library"
    if any(x in tech for x in ("apache", "nginx", "iis", "litespeed", "caddy")):
        return "Web Server"
    if any(x in tech for x in ("php", "python", "node.js", "nodejs", "asp.net", ".net")):
        return "Programming Language / Runtime"
    if any(x in tech for x in ("cloudflare", "cloudfront", "fastly", "akamai")):
        return "CDN / Security"
    if any(x in tech for x in ("google analytics", "google tag manager", "matomo", "hotjar", "facebook")):
        return "Analytics / Tracking"

    return "Technology"


def run_wappalyzer(target):
    """Run Wappalyzer as a secondary technology fingerprinting engine.

    Returns a list of normalized VectorSpy technology records plus engine metadata.
    Failure is intentionally non-fatal because the custom detector remains the
    primary fallback and Wappalyzer requires a working Playwright Chromium setup.
    """
    if Wappalyzer is None:
        return [], {
            "available": False,
            "status": "Unavailable",
            "error": "Wappalyzer package is not installed."
        }

    detections = []
    try:
        with Wappalyzer(workers=1, timeout=WAPPALYZER_TIMEOUT) as scanner:
            raw = scanner.analyze(target)

        for technology, data in (raw or {}).items():
            data = data or {}
            version = clean_text(data.get("version") or "Unknown", 80)
            category = wappalyzer_category(technology)

            confidence_raw = data.get("confidence", 85)
            try:
                confidence = int(float(confidence_raw))
            except (TypeError, ValueError):
                confidence = 85
            confidence = max(0, min(100, confidence))

            risk, recommendation = technology_risk(technology, version)

            evidence_parts = ["Wappalyzer fingerprint detected"]
            if version != "Unknown":
                evidence_parts.append(f"Detected version: {version}")

            detections.append({
                "name": category,
                "technology": clean_text(technology, 120),
                "version": version,
                "risk": risk,
                "evidence": "; ".join(evidence_parts),
                "confidence": confidence,
                "recommendation": recommendation,
                "source": "Wappalyzer"
            })

        return detections, {
            "available": True,
            "status": "Completed",
            "error": None,
            "count": len(detections)
        }

    except Exception as error:
        return [], {
            "available": True,
            "status": "Failed",
            "error": f"Wappalyzer scan failed: {error}"
        }

def find_technologies(target):
    if not target:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": "Target is required."
        }

    target = normalize_target(target)
    technologies = []

    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Connection": "close"
        }

        response = requests.get(
            target,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True
        )

        status = response.status_code
        final_url = response.url
        response_headers = response.headers
        server = response_headers.get("Server", "")
        powered_by = response_headers.get("X-Powered-By", "")
        via = response_headers.get("Via", "")
        cf_ray = response_headers.get("CF-Ray", "")
        cf_cache = response_headers.get("CF-Cache-Status", "")

        headers_text = "\n".join(
            f"{key}: {value}" for key, value in response_headers.items()
        )
        headers_lower = headers_text.lower()
        cookies_lower = " ".join(cookie.name for cookie in response.cookies).lower()

        content_type = response_headers.get("Content-Type", "").lower()
        raw_data = response.content[:MAX_HTML_SIZE]
        is_html = (
            "text/html" in content_type
            or "application/xhtml+xml" in content_type
            or not content_type
        )

        html = ""
        if is_html:
            encoding = response.encoding or "utf-8"
            html = raw_data.decode(encoding, errors="ignore")

        html_lower = html.lower()
        soup = BeautifulSoup(html, "html.parser")

        scripts, stylesheets, links = extract_resources(soup, final_url)
        resource_text = "\n".join(scripts + stylesheets + links).lower()

        page_title = clean_text(
            soup.title.get_text(" ", strip=True) if soup.title else "",
            300
        )

        generator_tags = soup.find_all(
            "meta", attrs={"name": re.compile(r"^generator$", re.I)}
        )
        generator_values = [
            clean_text(tag.get("content", ""), 250)
            for tag in generator_tags
            if clean_text(tag.get("content", ""), 250)
        ]

        # Web server detection
        server_lower = server.lower()

        if "nginx" in server_lower:
            version = extract_version([r"nginx/([\d.]+)"], server)
            risk, recommendation = technology_risk("nginx", version)
            add_technology(technologies, "Nginx", "Web Server", version,
                           f"Server header: {server}", risk, recommendation, 98)

        if "apache" in server_lower:
            version = extract_version([r"apache/([\d.]+)"], server)
            risk, recommendation = technology_risk("apache", version)
            add_technology(technologies, "Apache", "Web Server", version,
                           f"Server header: {server}", risk, recommendation, 98)

        if "microsoft-iis" in server_lower:
            version = extract_version([r"microsoft-iis/([\d.]+)"], server)
            add_technology(technologies, "Microsoft IIS", "Web Server", version,
                           f"Server header: {server}", "Medium",
                           "Keep IIS updated and review exposed services.", 98)

        if "litespeed" in server_lower:
            version = extract_version([r"litespeed(?:/|\s)([\d.]+)"], server)
            add_technology(technologies, "LiteSpeed", "Web Server", version,
                           f"Server header: {server}", "Low",
                           "Keep LiteSpeed updated and securely configured.", 98)

        if "caddy" in server_lower:
            version = extract_version([r"caddy[/\s]?([\d.]+)"], server)
            add_technology(technologies, "Caddy", "Web Server", version,
                           f"Server header: {server}", "Low",
                           "Keep Caddy updated and review server configuration.", 95)

        # PHP
        if "php" in powered_by.lower():
            version = extract_version([r"php[/\s-]?([\d.]+)"], powered_by)
            risk, recommendation = technology_risk("PHP", version)
            add_technology(technologies, "PHP", "Programming Language", version,
                           f"X-Powered-By: {powered_by}", risk, recommendation, 98)
        elif "phpsessid" in cookies_lower:
            add_technology(technologies, "PHP", "Programming Language", "Unknown",
                           "PHPSESSID cookie detected", "Medium",
                           "Keep PHP updated and review session configuration.", 80)
        elif re.search(r"\.php(?:[/?#]|$)", html_lower):
            risk, recommendation = technology_risk("PHP", "Unknown")
            add_technology(technologies, "PHP", "Programming Language", "Unknown",
                           ".php URL pattern detected", risk, recommendation, 75)

        # WordPress
        wp_version = "Unknown"
        for generator in generator_values:
            if "wordpress" in generator.lower():
                wp_version = extract_version([r"wordpress\s+([\d.]+)"], generator)
                add_technology(
                    technologies, "WordPress", "CMS", wp_version,
                    f"Generator meta tag: {generator}", "Medium",
                    "Keep WordPress core, themes and plugins updated.", 98
                )

        if "wp-content/" in html_lower:
            add_technology(
                technologies, "WordPress", "CMS", wp_version,
                "wp-content path detected", "Medium",
                "Keep WordPress core, themes and plugins updated.",
                95 if wp_version != "Unknown" else 90
            )

        if "wp-includes/" in html_lower:
            add_technology(
                technologies, "WordPress", "CMS", wp_version,
                "wp-includes path detected", "Medium",
                "Keep WordPress core, themes and plugins updated.", 95
            )

        # Drupal
        drupal_version = extract_version([r"Drupal\s+([\d.]+)"], html)
        if (
            "drupal-settings-json" in html_lower
            or "drupalsettings" in html_lower
            or "/sites/default/files/" in html_lower
        ):
            add_technology(
                technologies, "Drupal", "CMS", drupal_version,
                "Drupal resource fingerprint detected", "Medium",
                "Keep Drupal core and modules updated.", 90
            )

        # Joomla
        if (
            "/media/system/js/" in html_lower
            or "/media/jui/" in html_lower
            or "joomla!" in html_lower
        ):
            add_technology(
                technologies, "Joomla", "CMS", "Unknown",
                "Joomla resource fingerprint detected", "Medium",
                "Keep Joomla core and extensions updated.", 90
            )

        # Shopify
        if "cdn.shopify.com" in resource_text or "shopify" in html_lower:
            add_technology(
                technologies, "Shopify", "E-commerce", "Unknown",
                "Shopify fingerprint detected", "Low",
                "Review Shopify applications and third-party integrations.", 95
            )

        # React
        if (
            "__react" in html_lower
            or "_reactroot" in html_lower
            or "react-dom" in resource_text
            or "react.production" in resource_text
            or "react.development" in resource_text
        ):
            version = extract_version(
                [r"react(?:@|/|-)([\d.]+)"], resource_text
            )
            add_technology(
                technologies, "React", "JavaScript Framework", version,
                "React JavaScript fingerprint detected", "Low",
                "Keep React and related dependencies updated.",
                95 if version != "Unknown" else 90
            )

        # Vue
        if (
            "vue.js" in resource_text
            or "vue.min.js" in resource_text
            or "__vue__" in html_lower
            or "data-v-" in html_lower
        ):
            version = extract_version(
                [r"vue(?:@|/|-)([\d.]+)"], resource_text
            )
            add_technology(
                technologies, "Vue.js", "JavaScript Framework", version,
                "Vue.js fingerprint detected", "Low",
                "Keep Vue.js and related dependencies updated.",
                95 if version != "Unknown" else 90
            )

        # Angular
        angular_version = "Unknown"
        ng_element = soup.find(attrs={"ng-version": True})
        if ng_element:
            angular_version = clean_text(ng_element.get("ng-version"), 50)

        if ng_element or "angular.js" in resource_text or "@angular/" in resource_text:
            if angular_version == "Unknown":
                angular_version = extract_version(
                    [r"angular(?:@|/|-)([\d.]+)"], resource_text
                )
            add_technology(
                technologies, "Angular", "JavaScript Framework",
                angular_version, "Angular fingerprint detected", "Medium",
                "Keep Angular and npm dependencies updated.",
                98 if angular_version != "Unknown" else 90
            )

        # Next.js / Nuxt
        if soup.find(id="__NEXT_DATA__") or "/_next/static/" in resource_text:
            version = extract_version(
                [r"next(?:@|/|-)([\d.]+)"], resource_text
            )
            add_technology(
                technologies, "Next.js", "Web Framework", version,
                "Next.js _next/static fingerprint detected", "Low",
                "Keep Next.js and npm dependencies updated.",
                98 if version != "Unknown" else 95
            )

        if "__nuxt__" in html_lower or "_nuxt/" in resource_text:
            add_technology(
                technologies, "Nuxt.js", "Web Framework", "Unknown",
                "Nuxt.js _nuxt resource fingerprint detected", "Low",
                "Keep Nuxt.js and dependencies updated.", 95
            )

        # jQuery
        if "jquery" in resource_text or "jquery" in html_lower:
            version = extract_version(
                [
                    r"jquery[-.]([\d.]+)",
                    r"jquery@([\d.]+)",
                    r"jquery/([\d.]+)"
                ],
                resource_text
            )
            add_technology(
                technologies, "jQuery", "JavaScript Library", version,
                "jQuery resource fingerprint detected", "Medium",
                "Keep jQuery updated and remove unused dependencies.",
                98 if version != "Unknown" else 88
            )

        # Bootstrap
        if "bootstrap" in resource_text:
            version = extract_version(
                [r"bootstrap[-.]([\d.]+)", r"bootstrap@([\d.]+)"],
                resource_text
            )
            add_technology(
                technologies, "Bootstrap", "CSS Framework", version,
                "Bootstrap resource detected", "Low",
                "Keep Bootstrap and frontend dependencies updated.",
                98 if version != "Unknown" else 90
            )

        # Tailwind
        if "tailwind" in resource_text or "tailwindcss" in html_lower:
            add_technology(
                technologies, "Tailwind CSS", "CSS Framework", "Unknown",
                "Tailwind CSS fingerprint detected", "Low",
                "Keep frontend dependencies updated.", 90
            )

        # Font Awesome
        if "font-awesome" in resource_text or "fontawesome" in resource_text:
            version = extract_version(
                [r"font[-]?awesome[/@-]?([\d.]+)"], resource_text
            )
            add_technology(
                technologies, "Font Awesome", "UI Library", version,
                "Font Awesome resource detected", "Low",
                "Keep frontend libraries updated.", 90
            )

        # Laravel
        if "laravel_session" in cookies_lower or "laravel" in html_lower:
            add_technology(
                technologies, "Laravel", "PHP Framework", "Unknown",
                "Laravel fingerprint detected", "Medium",
                "Keep Laravel and Composer dependencies updated.", 90
            )

        # ASP.NET
        if (
            "asp.net" in powered_by.lower()
            or "aspnet" in cookies_lower
            or "__viewstate" in html_lower
        ):
            version = extract_version(
                [r"asp\.net[/\s-]?([\d.]+)"], powered_by
            )
            add_technology(
                technologies, "ASP.NET", "Web Framework", version,
                "ASP.NET fingerprint detected", "Medium",
                "Keep ASP.NET and .NET runtime updated.", 95
            )

        # Cloudflare
        if (
            cf_ray
            or cf_cache
            or "cloudflare" in server_lower
            or "cloudflare" in headers_lower
        ):
            evidence = []
            if cf_ray:
                evidence.append("CF-Ray header")
            if cf_cache:
                evidence.append("CF-Cache-Status header")
            if "cloudflare" in server_lower:
                evidence.append(f"Server header: {server}")

            add_technology(
                technologies, "Cloudflare", "CDN / Security", "Unknown",
                ", ".join(evidence), "Low",
                "Review CDN configuration, TLS settings and security rules.", 98
            )

        # CloudFront
        if "cloudfront" in headers_lower or "cloudfront.net" in resource_text:
            add_technology(
                technologies, "Amazon CloudFront", "CDN", "Unknown",
                "CloudFront header/resource fingerprint detected", "Low",
                "Review CDN and caching configuration.", 95
            )

        # Fastly
        if "fastly" in headers_lower or "fastly" in via.lower():
            add_technology(
                technologies, "Fastly", "CDN", "Unknown",
                "Fastly header fingerprint detected", "Low",
                "Review CDN configuration and cache controls.", 95
            )

        # Analytics
        if (
            "google-analytics.com" in resource_text
            or "googletagmanager.com/gtag" in resource_text
            or "gtag(" in html_lower
            or "google-analytics" in html_lower
        ):
            add_technology(
                technologies, "Google Analytics", "Analytics", "Unknown",
                "Google Analytics script fingerprint detected", "Low",
                "Review analytics configuration and data privacy settings.", 98
            )

        if "googletagmanager.com" in resource_text or "gtm-" in html_lower:
            add_technology(
                technologies, "Google Tag Manager", "Tag Manager", "Unknown",
                "Google Tag Manager fingerprint detected", "Low",
                "Review third-party tags and tracking configuration.", 98
            )

        if "connect.facebook.net" in resource_text or "fbq(" in html_lower:
            add_technology(
                technologies, "Meta Pixel", "Analytics", "Unknown",
                "Meta Pixel JavaScript fingerprint detected", "Low",
                "Review third-party tracking and privacy configuration.", 95
            )

        # Generic generator
        for generator in generator_values:
            if any(x in generator.lower() for x in ("wordpress", "drupal", "joomla")):
                continue

            name = generator.split()[0] if generator.split() else "Unknown"

            add_technology(
                technologies,
                name,
                "Generator",
                extract_version([r"[\s/]([\d.]+)"], generator),
                f"Generator meta tag: {generator}",
                "Low",
                "Review exposed technology information and keep the platform updated.",
                85
            )

        # Secondary detection engine: Wappalyzer
        # Custom detection above remains active and results are merged/deduplicated.
        wappalyzer_results, wappalyzer_meta = run_wappalyzer(final_url)
        for item in wappalyzer_results:
            add_technology(
                technologies,
                item.get("technology", ""),
                item.get("name", "Technology"),
                item.get("version", "Unknown"),
                item.get("evidence", "Wappalyzer fingerprint detected"),
                item.get("risk", "Low"),
                item.get("recommendation", "Keep the technology updated."),
                item.get("confidence", 85)
            )

        technologies.sort(
            key=lambda x: (-x.get("confidence", 0),
                           x.get("technology", "").lower())
        )

        return {
            "target": target,
            "final_url": final_url,
            "status": status,
            "page_title": page_title,
            "content_type": content_type,
            "response_time": response.elapsed.total_seconds(),
            "technologies": technologies,
            "technology_count": len(technologies),
            "detection_engines": {
                "custom": {"available": True, "status": "Completed"},
                "wappalyzer": wappalyzer_meta
            },
            "resource_summary": {
                "scripts": len(scripts),
                "stylesheets": len(stylesheets),
                "links": len(links)
            },
            "scripts": scripts[:100],
            "stylesheets": stylesheets[:100],
            "links": links[:100],
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": "Technology scan timed out."
        }

    except requests.exceptions.SSLError:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": "TLS/SSL certificate verification failed."
        }

    except requests.exceptions.ConnectionError as error:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": f"Connection error: {error}"
        }

    except requests.exceptions.RequestException as error:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": f"HTTP request error: {error}"
        }

    except Exception as error:
        return {
            "target": target, "status": None, "page_title": "",
            "technologies": [], "technology_count": 0,
            "error": str(error)
        }


def scan_target(target):
    return find_technologies(target)
