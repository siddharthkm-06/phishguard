from urllib.parse import urlparse, parse_qs, unquote
import tldextract

def normalize_url(url: str) -> str:
    """
    Adds http:// if missing and trims whitespace.
    """
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        url = "http://" + url
    return url

def is_ip_address(hostname: str) -> bool:
    """
    Simple IPv4 detection without external libs.
    """
    if not hostname:
        return False
    parts = hostname.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def parse_url(url: str) -> dict:
    """
    Parse URL into useful components for phishing analysis.
    """
    result = {"raw": url}

    if not url or not url.strip():
        return result

    # Normalize
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    result["normalized"] = normalized
    result["scheme"] = parsed.scheme
    result["netloc"] = parsed.netloc
    result["path"] = parsed.path
    result["query"] = parsed.query
    result["params"] = parsed.params
    result["fragment"] = parsed.fragment
    result["hostname"] = parsed.hostname
    result["port"] = parsed.port

    # Query params
    try:
        result["query_params"] = parse_qs(parsed.query)
    except Exception:
        result["query_params"] = {}

    # Path segments
    segments = [seg for seg in parsed.path.split("/") if seg]
    result["path_segments"] = [unquote(seg) for seg in segments]

    # Extract domain parts using tldextract
    try:
        ext = tldextract.extract(normalized)
        result["subdomain"] = ext.subdomain or ""
        result["domain"] = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        result["fqdn"] = ".".join(
            part for part in [ext.subdomain, ext.domain, ext.suffix] if part
        )
        result["suffix"] = ext.suffix or ""
    except Exception:
        result["subdomain"] = ""
        result["domain"] = result.get("hostname", "") or ""
        result["fqdn"] = result.get("hostname", "") or ""
        result["suffix"] = ""

    # Derived checks
    result["num_subdomains"] = (
        len(result["subdomain"].split(".")) if result["subdomain"] else 0
    )
    result["netloc_contains_at"] = "@" in (result.get("netloc") or "")
    result["is_ip_address"] = is_ip_address(result.get("hostname") or "")

    return result
