"""
Attack Surface and Domain Security Health Checker
Inspects SSL certificates, DNS/Mail authentication (SPF/DMARC), and HTTP security headers.
"""
import ssl
import socket
import logging
from datetime import datetime
import requests
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger(__name__)

def check_ssl_certificate(domain, port=443, timeout=5):
    """Inspects the SSL certificate of a domain."""
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    elif clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    result = {
        "domain": clean_domain,
        "has_ssl": False,
        "issuer": "N/A",
        "subject": "N/A",
        "valid_from": None,
        "valid_to": None,
        "days_left": None,
        "status": "Sin SSL / Inalcanzable",
        "tls_version": "N/A",
        "error": None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                # Extract dates
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                
                # Format: 'May 12 12:00:00 2026 GMT'
                dt_format = "%b %d %H:%M:%S %Y %Z"
                dt_from = datetime.strptime(not_before_str, dt_format) if not_before_str else None
                dt_to = datetime.strptime(not_after_str, dt_format) if not_after_str else None
                
                now = datetime.utcnow()
                days_left = (dt_to - now).days if dt_to else None

                # Extract Issuer & Subject Org/CN
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Desconocido")
                subject_name = subject_dict.get("commonName") or subject_dict.get("organizationName", clean_domain)

                status = "Válido"
                if days_left is not None:
                    if days_left <= 0:
                        status = "Expirado"
                    elif days_left <= 30:
                        status = "Por Expirar (<30 días)"

                result.update({
                    "has_ssl": True,
                    "issuer": issuer_name,
                    "subject": subject_name,
                    "valid_from": dt_from.strftime("%Y-%m-%d") if dt_from else None,
                    "valid_to": dt_to.strftime("%Y-%m-%d") if dt_to else None,
                    "days_left": days_left,
                    "status": status,
                    "tls_version": tls_version
                })
    except Exception as e:
        result["error"] = str(e)

    return result

def check_dns_security(domain):
    """Checks DNS records, SPF, and DMARC."""
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    elif clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    result = {
        "ip_addresses": [],
        "mx_records": [],
        "has_spf": False,
        "spf_record": None,
        "has_dmarc": False,
        "dmarc_record": None
    }

    # 1. IP resolution
    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        ips = sorted(list(set(item[4][0] for item in addr_info if item[4])))
        result["ip_addresses"] = ips[:5]
    except Exception:
        pass

    if not DNS_AVAILABLE:
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 2. MX records
    try:
        mx_answers = resolver.resolve(clean_domain, "MX")
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_answers][:5]
    except Exception:
        pass

    # 3. SPF check (TXT record with v=spf1)
    try:
        txt_answers = resolver.resolve(clean_domain, "TXT")
        for r in txt_answers:
            txt_str = "".join([part.decode("utf-8", errors="ignore") for part in r.strings])
            if txt_str.lower().startswith("v=spf1"):
                result["has_spf"] = True
                result["spf_record"] = txt_str
                break
    except Exception:
        pass

    # 4. DMARC check (_dmarc.domain)
    try:
        dmarc_domain = f"_dmarc.{clean_domain}"
        dmarc_answers = resolver.resolve(dmarc_domain, "TXT")
        for r in dmarc_answers:
            txt_str = "".join([part.decode("utf-8", errors="ignore") for part in r.strings])
            if "v=dmarc1" in txt_str.lower():
                result["has_dmarc"] = True
                result["dmarc_record"] = txt_str
                break
    except Exception:
        pass

    return result

def check_http_security_headers(domain, timeout=5):
    """Analyzes security headers for a domain over HTTPS/HTTP."""
    clean_domain = domain.strip().lower()
    if not clean_domain.startswith("http://") and not clean_domain.startswith("https://"):
        target_url = f"https://{clean_domain}"
    else:
        target_url = clean_domain

    headers_audit = {
        "Strict-Transport-Security": {"present": False, "value": None, "score": 25},
        "Content-Security-Policy": {"present": False, "value": None, "score": 25},
        "X-Frame-Options": {"present": False, "value": None, "score": 15},
        "X-Content-Type-Options": {"present": False, "value": None, "score": 15},
        "Referrer-Policy": {"present": False, "value": None, "score": 10},
        "Permissions-Policy": {"present": False, "value": None, "score": 10}
    }

    result = {
        "url": target_url,
        "status_code": 0,
        "score": 0,
        "grade": "F",
        "headers": {},
        "missing_headers": []
    }

    try:
        resp = requests.get(
            target_url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Compatible; BrandSentinelSecurityBot/1.0)"},
            allow_redirects=True,
            verify=False
        )
        result["status_code"] = resp.status_code
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        total_score = 0
        for header_name, meta in headers_audit.items():
            h_lower = header_name.lower()
            if h_lower in resp_headers:
                meta["present"] = True
                meta["value"] = resp_headers[h_lower][:150]
                total_score += meta["score"]
                result["headers"][header_name] = meta["value"]
            else:
                result["missing_headers"].append(header_name)

        result["score"] = total_score
        if total_score >= 85:
            result["grade"] = "A+"
        elif total_score >= 70:
            result["grade"] = "A"
        elif total_score >= 50:
            result["grade"] = "B"
        elif total_score >= 30:
            result["grade"] = "C"
        else:
            result["grade"] = "D" if total_score > 0 else "F"

    except Exception as e:
        result["error"] = str(e)
        result["missing_headers"] = list(headers_audit.keys())

    return result

def audit_domain_surface(domain):
    """
    Comprehensive Attack Surface Audit for a single domain.
    """
    ssl_data = check_ssl_certificate(domain)
    dns_data = check_dns_security(domain)
    headers_data = check_http_security_headers(domain)

    # Global Health Score (0 - 100)
    health_points = 0
    if ssl_data.get("has_ssl") and ssl_data.get("status") == "Válido":
        health_points += 35
    elif ssl_data.get("has_ssl"):
        health_points += 15

    if dns_data.get("has_spf"):
        health_points += 15
    if dns_data.get("has_dmarc"):
        health_points += 15

    health_points += int(headers_data.get("score", 0) * 0.35)

    return {
        "domain": domain,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "health_score": min(100, health_points),
        "ssl": ssl_data,
        "dns": dns_data,
        "http_headers": headers_data
    }
