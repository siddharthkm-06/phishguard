
import re
from typing import Tuple, List
import os

# load whitelist if present
WHITELIST = set()
wl_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "whitelist.txt")

if os.path.isfile(wl_path):
    try:
        with open(wl_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip().lower()
                if domain:
                    WHITELIST.add(domain)
    except Exception:
        WHITELIST = set()



# Small, easy-to-edit lists
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure-login", "update", "reset", "account", "signin", "confirm",
    "bank", "password", "confirm-account", "verify-account", "secure"
]
SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq"]  # often abused
COMMON_BRAND_HINTS = ["paypal", "bank", "apple", "google", "amazon"]

def rule_is_ip(parsed: dict) -> Tuple[int, str]:
    if parsed.get("is_ip_address"):
        return 25, "URL uses IP address instead of domain"
    return 0, ""

def rule_netloc_contains_at(parsed: dict) -> Tuple[int, str]:
    if parsed.get("netloc_contains_at"):
        return 30, "URL contains '@' in netloc (credential/redirect trick)"
    return 0, ""

def rule_too_many_subdomains(parsed: dict) -> Tuple[int, str]:
    if parsed.get("num_subdomains", 0) >= 3:
        return 15, "Many subdomains (possible obfuscation)"
    return 0, ""

def rule_suspicious_tld(parsed: dict) -> Tuple[int, str]:
    suffix = (parsed.get("suffix") or "").lower()
    if suffix in SUSPICIOUS_TLDS:
        return 10, f"Suspicious top level domain: .{suffix}"
    return 0, ""

def rule_suspicious_keyword(parsed: dict) -> Tuple[int, str]:
    """
    If the URL contains phishing-like keywords (login, verify, reset, etc.),
    return a score unless the domain is whitelisted.
    """
    # domain full like 'paypal.com'
    domain_full = (parsed.get("domain") or "").lower()

    # If the project-wide WHITELIST exists and domain is whitelisted, skip keyword checks
    try:
        if domain_full in WHITELIST:
            return 0, ""
    except NameError:
        # If WHITELIST is not defined for any reason, continue normally
        pass

    url = (parsed.get("normalized") or "").lower()
    hits: List[str] = [k for k in SUSPICIOUS_KEYWORDS if k in url]
    if hits:
        return 15, f"Contains phishing-like keyword(s): {', '.join(hits)}"
    return 0, "" ""

def rule_long_query(parsed: dict) -> Tuple[int, str]:
    query = parsed.get("query") or ""
    if len(query) > 60:
        return 8, "Long query string detected"
    return 0, ""

def rule_domain_lookalike(parsed: dict) -> Tuple[int, str]:
    """
    Basic heuristic: check if domain contains common brand with small edit distance /
    character substitutions like 'paypa1' for 'paypal' (we check simple character toggles).
    We'll look for common brand hints inside domain and suspicious similarity like replacing 'l' with '1' etc.
    """
    domain = (parsed.get("domain") or "").lower()
    reasons = []
    score = 0
    for brand in COMMON_BRAND_HINTS:
        if brand in domain and domain != f"{brand}.com":
            score += 25
            reasons.append(f"Domain contains brand-like token: {brand}")
        # check simple visual substitutions
        variants = [
            domain.replace("1", "l"),
            domain.replace("0", "o"),
            domain.replace("5", "s"),
        ]
        for v in variants:
            if v.endswith(brand) and v != domain:
                score += 25
                reasons.append(f"Domain visually similar to brand: {brand}")
                break
    if score:
        return score, "; ".join(reasons)
    return 0, ""

# add near other rules in core/rules.py
from rapidfuzz import fuzz

def rule_similarity_levenshtein(parsed: dict) -> tuple:

    
    """
    Use fuzzy string similarity (rapidfuzz) to detect domains that are *very* similar
    to common brands (e.g., paypa1 ~ paypal). We compare the raw domain (without suffix)
    to known brand tokens and give points when similarity is high.
    """
    domain_full = (parsed.get("domain") or "").lower()
    if domain_full in WHITELIST:
        return 0, ""

    domain = (parsed.get("domain") or "").lower()
    # domain may be "paypa1.com" -> strip suffix for similarity check
    domain_label = domain.split(".")[0] if domain else ""
    score = 0
    reasons = []
    if not domain_label:
        return 0, ""

    for brand in COMMON_BRAND_HINTS:
        # compute ratio; fuzz.ratio returns 0-100
        ratio = fuzz.ratio(domain_label, brand)
        # also check partial_ratio to handle extra prefixes/suffixes
        pr = fuzz.partial_ratio(domain_label, brand)
        # choose the stronger signal
        best = max(ratio, pr)
        if best >= 85 and domain_label != brand:
            score += 30
            reasons.append(f"High similarity to brand '{brand}' (score {best})")
        elif best >= 70 and domain_label != brand:
            score += 15
            reasons.append(f"Moderate similarity to brand '{brand}' (score {best})")

    if score:
        return score, "; ".join(reasons)
    return 0, ""


def rule_at_path_or_query(parsed: dict) -> Tuple[int, str]:
    """
    If path or query contains an email-like token or credential-like token with @,
    it probably uses trickery.
    """
    combined = (parsed.get("normalized") or "")
    if "@" in combined and not parsed.get("netloc_contains_at"):
        # If @ exists in path or query rather than netloc
        return 20, "Contains '@' in path or query (suspicious)"
    return 0, ""

def apply_all_rules(parsed: dict) -> list:
    """
    Return list of (score, reason) tuples
    """
    checks = [
        rule_is_ip,
        rule_netloc_contains_at,
        rule_too_many_subdomains,
        rule_suspicious_tld,
        rule_suspicious_keyword,
        rule_long_query,
        rule_domain_lookalike,
        rule_similarity_levenshtein,
        rule_at_path_or_query,
    ]
    results = []
    for fn in checks:
        try:
            s, r = fn(parsed)
            if s and r:
                results.append((s, r))
        except Exception as e:
            # don't break on a single rule failure
            results.append((0, f"rule_error:{fn.__name__}:{str(e)}"))
    return results
