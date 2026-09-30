import socket
from urllib.parse import urlparse


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "ftp",
    "api",
    "app",
    "portal",
    "admin",
    "login",
    "auth",
    "dev",
    "test",
    "staging",
    "demo",
    "beta",
    "support",
    "help",
    "blog",
    "shop",
    "store",
    "cdn",
    "static",
    "assets",
    "media",
    "docs",
    "status",
]


def normalize_domain(target):
    target = target.strip()

    if not target:
        return ""

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    domain = parsed.hostname or ""

    return domain.lower().strip(".")


def is_valid_domain(domain):
    if not domain:
        return False

    if "." not in domain:
        return False

    if " " in domain:
        return False

    if len(domain) > 253:
        return False

    return True


def find_subdomains(target):
    domain = normalize_domain(target)

    if not is_valid_domain(domain):
        return {
            "error": "Please enter a valid domain such as example.com.",
            "domain": domain,
            "subdomains": [],
            "total": 0,
        }

    results = []
    seen = set()

    for prefix in COMMON_SUBDOMAINS:

        hostname = f"{prefix}.{domain}"

        if hostname in seen:
            continue

        seen.add(hostname)

        try:

            ip_address = socket.gethostbyname(hostname)

            results.append(
                {
                    "subdomain": hostname,
                    "ip_address": ip_address,
                    "status": "Active",
                }
            )

        except socket.gaierror:

            # DNS name could not be resolved.
            continue

        except Exception:

            continue

    return {
        "error": "",
        "domain": domain,
        "subdomains": results,
        "total": len(results),
    }
