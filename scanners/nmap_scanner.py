import ipaddress
import re
import time

import nmap

NMAP_TIMEOUT = 120


def _validate_target(target):
    if not target:
        return False, "Target is required."
    target = str(target).strip()
    if len(target) > 253:
        return False, "Target is too long."
    try:
        ipaddress.ip_address(target)
        return True, ""
    except ValueError:
        pass
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )
    if hostname_pattern.match(target):
        return True, ""
    return False, "Invalid target. Enter a valid hostname or IP address."


def _clean(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(x).strip() for x in value if str(x).strip())
    return str(value).strip()


def _normalize_cpe(cpe):
    return _clean(cpe)


def _parse_port_filter(port_filter):
    """Validate custom TCP ports and return an Nmap -p expression."""
    if not port_filter:
        return ""
    value = str(port_filter).strip().replace(" ", "")
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("Invalid port filter. Use examples: 22,80,443 or 1-1000.")
    parts = []
    for item in value.split(","):
        if "-" in item:
            a, b = map(int, item.split("-", 1))
            if not (1 <= a <= b <= 65535):
                raise ValueError("Port range must be between 1 and 65535.")
        else:
            p = int(item)
            if not 1 <= p <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
        parts.append(item)
    return ",".join(parts)


def _scan_arguments(scan_mode, port_filter):
    mode = (scan_mode or "balanced").strip().lower()
    if mode not in {"fast", "balanced", "accurate"}:
        mode = "balanced"

    custom_ports = _parse_port_filter(port_filter)

    if custom_ports:
        port_arg = f"-p {custom_ports}"
    elif mode == "fast":
        port_arg = "--top-ports 100"
    else:
        port_arg = "--top-ports 1000"

    if mode == "fast":
        args = f"-sT -T4 {port_arg} --reason"
    elif mode == "accurate":
        args = f"-sT -T3 {port_arg} -sV --version-all --reason"
    else:
        args = f"-sT -T4 {port_arg} -sV --version-light --reason"

    return mode, args


def _calculate_confidence(service, product, version, extrainfo, service_fp, cpe, reason):
    confidence = 35
    if service:
        confidence += 15
    if product:
        confidence += 15
    if version:
        confidence += 15
    if extrainfo:
        confidence += 5
    if service_fp:
        confidence += 5
    if cpe:
        confidence += 5
    if reason:
        confidence += 5
    return min(confidence, 100)


def _build_evidence(port, protocol, state, service, product, version,
                    extrainfo, tunnel, service_fp, reason, reason_ttl, cpe):
    parts = [f"{port}/{protocol}", f"state={state}"]
    if service:
        parts.append(f"service={service}")
    if product:
        parts.append(f"product={product}")
    if version:
        parts.append(f"version={version}")
    if extrainfo:
        parts.append(f"info={extrainfo}")
    if tunnel:
        parts.append(f"tunnel={tunnel}")
    if service_fp:
        parts.append(f"servicefp={service_fp}")
    if reason:
        parts.append(f"reason={reason}")
    if reason_ttl:
        parts.append(f"reason_ttl={reason_ttl}")
    if cpe:
        parts.append(f"cpe={cpe}")
    return " | ".join(parts)


def _run_nmap(scanner, target, arguments):
    """Run one bounded Nmap pass."""
    scanner.scan(
        hosts=target,
        arguments=arguments,
        timeout=NMAP_TIMEOUT
    )


def _extract_port_data(scanner, host):
    """Extract TCP port records from an Nmap host result."""
    records = []
    if "tcp" not in scanner[host]:
        return records
    for port in sorted(scanner[host]["tcp"].keys()):
        data = scanner[host]["tcp"][port]
        records.append((port, data))
    return records


def _apply_service_details(port_record, detail_record):
    """Merge service/version details from the second Nmap pass."""
    if not detail_record:
        return
    for key in (
        "name", "product", "version", "extrainfo", "tunnel",
        "servicefp", "reason", "reason_ttl", "cpe"
    ):
        if key in detail_record:
            port_record[key] = detail_record[key]


def scan_target(target, scan_mode="balanced", port_filter=""):
    """Run an authorized, optimized two-stage Nmap TCP assessment.

    Stage 1 performs fast TCP state discovery.
    Stage 2 performs service/version detection only on open ports.
    Fast mode intentionally stops after discovery for maximum speed.
    """
    started = time.perf_counter()

    try:
        target = str(target or "").strip()
        valid, validation_error = _validate_target(target)
        if not valid:
            return [{"error": validation_error}]

        mode = (scan_mode or "balanced").strip().lower()
        if mode not in {"fast", "balanced", "accurate"}:
            mode = "balanced"

        custom_ports = _parse_port_filter(port_filter)

        # Keep the requested scan scope. Custom ports always override profile scope.
        if custom_ports:
            port_arg = f"-p {custom_ports}"
        elif mode == "fast":
            port_arg = "--top-ports 100"
        else:
            port_arg = "--top-ports 1000"

        # Stage 1: state discovery. -n avoids reverse-DNS delays.
        discovery_args = f"-sT -T4 -n {port_arg} --reason"
        scanner = nmap.PortScanner()
        _run_nmap(scanner, target, discovery_args)

        hosts = scanner.all_hosts()
        elapsed_discovery = round(time.perf_counter() - started, 2)

        if not hosts:
            return [{
                "error": "Target could not be resolved or no host was found.",
                "scan_mode": mode,
                "scan_time": elapsed_discovery,
            }]

        results = []

        for host in hosts:
            host_state = "unknown"
            try:
                host_state = scanner[host].state()
            except Exception:
                pass

            host_data = {
                "host": host,
                "ip": host,
                "hostname": "",
                "state": host_state,
                "scan_mode": mode,
                "scan_time": 0,
                "ports": [],
                "summary": {"open": 0, "closed": 0, "filtered": 0, "other": 0},
            }

            # Hostnames are retained from Nmap when available.
            try:
                for hostname_info in scanner[host].hostnames():
                    hostname = _clean(hostname_info.get("name", ""))
                    if hostname:
                        host_data["hostname"] = hostname
                        break
            except Exception:
                pass

            open_ports = []

            # Build state records from discovery pass.
            for port, data in _extract_port_data(scanner, host):
                state = _clean(data.get("state", "")).lower()

                if state == "open":
                    host_data["summary"]["open"] += 1
                    open_ports.append(port)
                elif state == "closed":
                    host_data["summary"]["closed"] += 1
                elif state in {"filtered", "open|filtered", "closed|filtered"}:
                    host_data["summary"]["filtered"] += 1
                else:
                    host_data["summary"]["other"] += 1

                host_data["ports"].append({
                    "port": str(port),
                    "protocol": "tcp",
                    "state": state,
                    "service": _clean(data.get("name", "")),
                    "product": _clean(data.get("product", "")),
                    "version": _clean(data.get("version", "")) or "Unknown",
                    "confidence": 35,
                    "evidence": _build_evidence(
                        port, "tcp", state,
                        _clean(data.get("name", "")),
                        _clean(data.get("product", "")),
                        _clean(data.get("version", "")),
                        _clean(data.get("extrainfo", "")),
                        _clean(data.get("tunnel", "")),
                        _clean(data.get("servicefp", "")),
                        _clean(data.get("reason", "")),
                        _clean(data.get("reason_ttl", "")),
                        _normalize_cpe(data.get("cpe", ""))
                    ),
                    "extrainfo": _clean(data.get("extrainfo", "")),
                    "tunnel": _clean(data.get("tunnel", "")),
                    "cpe": _normalize_cpe(data.get("cpe", "")),
                    "servicefp": _clean(data.get("servicefp", "")),
                    "reason": _clean(data.get("reason", "")),
                    "reason_ttl": _clean(data.get("reason_ttl", "")),
                })

            # Fast mode ends after port-state discovery.
            if mode != "fast" and open_ports:
                open_port_expression = ",".join(str(p) for p in open_ports)
                if mode == "accurate":
                    detail_args = (
                        f"-sT -T4 -n -p {open_port_expression} "
                        f"-sV --version-all --reason"
                    )
                else:
                    detail_args = (
                        f"-sT -T4 -n -p {open_port_expression} "
                        f"-sV --version-light --reason"
                    )

                detail_scanner = nmap.PortScanner()
                _run_nmap(detail_scanner, host, detail_args)

                if host in detail_scanner.all_hosts():
                    detail_records = dict(_extract_port_data(detail_scanner, host))
                    for port_result in host_data["ports"]:
                        port_number = int(port_result["port"])
                        detail = detail_records.get(port_number)
                        if not detail:
                            continue

                        service = _clean(detail.get("name", ""))
                        product = _clean(detail.get("product", ""))
                        version = _clean(detail.get("version", ""))
                        extrainfo = _clean(detail.get("extrainfo", ""))
                        tunnel = _clean(detail.get("tunnel", ""))
                        service_fp = _clean(detail.get("servicefp", ""))
                        reason = _clean(detail.get("reason", ""))
                        reason_ttl = _clean(detail.get("reason_ttl", ""))
                        cpe = _normalize_cpe(detail.get("cpe", ""))

                        version_parts = [x for x in (product, version) if x]
                        if extrainfo:
                            version_parts.append(f"({extrainfo})")
                        version_text = " ".join(version_parts) or "Unknown"

                        port_result.update({
                            "service": service,
                            "product": product,
                            "version": version_text,
                            "confidence": _calculate_confidence(
                                service, product, version, extrainfo,
                                service_fp, cpe, reason
                            ),
                            "extrainfo": extrainfo,
                            "tunnel": tunnel,
                            "cpe": cpe,
                            "servicefp": service_fp,
                            "reason": reason,
                            "reason_ttl": reason_ttl,
                            "evidence": _build_evidence(
                                port_number, "tcp", port_result["state"],
                                service, product, version, extrainfo,
                                tunnel, service_fp, reason, reason_ttl, cpe
                            ),
                        })

            host_data["scan_time"] = round(time.perf_counter() - started, 2)
            results.append(host_data)

        total_time = round(time.perf_counter() - started, 2)
        for host_data in results:
            host_data["scan_time"] = total_time

        return results

    except ValueError as e:
        return [{"error": str(e)}]
    except nmap.PortScannerError as e:
        return [{"error": f"Nmap scanner error: {str(e)}"}]
    except Exception as e:
        return [{"error": f"Nmap scan failed: {type(e).__name__}: {str(e)}"}]
