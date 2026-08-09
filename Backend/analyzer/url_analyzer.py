import re
import difflib
from typing import List, Dict, Tuple
from urllib.parse import urlparse

TRUSTED_DOMAINS = [
    "parivahan.gov.in",
    "echallan.parivahan.gov.in",
    "onlineservices.mp.gov.in",
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "rbi.org.in"
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "cutt.ly",
    "t.co"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".info",
    ".top",
    ".click"
]

def extract_urls(text: str) -> List[str]:
    """
    Extracts URLs/domains from arbitrary text.
    Handles http://, https://, www., and naked domains with paths.
    """
    # Pattern matching http(s):// or www. or generic domain patterns
    pattern = r'(https?://\S+|www\.\S+|\b[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\b\S*)'
    raw_matches = re.findall(pattern, text)
    urls = []
    
    for match in raw_matches:
        # Strip trailing punctuation commonly appended in sentences
        cleaned = match.rstrip('.,;:?!)]}"\'')
        
        # Skip APK filenames if they aren't part of a web protocol/URI
        if cleaned.lower().endswith('.apk') and not (cleaned.lower().startswith('http') or cleaned.lower().startswith('www')):
            continue
            
        # Ensure it has a dot to be a valid domain/URL and is long enough
        if '.' in cleaned and len(cleaned) > 3:
            urls.append(cleaned)
            
    return list(dict.fromkeys(urls)) # Remove duplicates while preserving order

def get_domain(url: str) -> str:
    """
    Extracts the hostname/domain from a URL.
    Prepends http:// if no scheme is present to enable parsing.
    """
    parsed_url = url
    if not (url.lower().startswith('http://') or url.lower().startswith('https://')):
        parsed_url = 'http://' + url
        
    try:
        parsed = urlparse(parsed_url)
        netloc = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        return netloc.lower()
    except Exception:
        # Fallback if URL parsing fails
        return url.split('/')[0].lower()

def is_trusted_domain(domain: str) -> bool:
    """
    Checks if a domain is trusted.
    A domain is trusted if it's an exact match or a subdomain of a trusted domain.
    """
    check_domain = domain
    if check_domain.startswith("www."):
        check_domain = check_domain[4:]
        
    for trusted in TRUSTED_DOMAINS:
        if check_domain == trusted:
            return True
        if check_domain.endswith("." + trusted):
            return True
            
    return False

def analyze_domain(domain: str) -> Tuple[str, str]:
    """
    Analyzes a domain to determine if it is trusted, suspicious, or neutral.
    Returns: (status, reason)
    """
    check_domain = domain
    if check_domain.startswith("www."):
        check_domain = check_domain[4:]
        
    # 1. Check if Trusted
    if is_trusted_domain(domain):
        return "trusted", "Trusted official domain"
        
    # 2. Check if URL Shortener
    if check_domain in SHORTENER_DOMAINS:
        return "suspicious", "Shortened links hide the real destination website and make it harder to verify where the link leads."
        
    # 3. Check for keywords of trusted brands (spoofing)
    brand_keywords = ["sbi", "hdfc", "icici", "parivahan", "challan", "rbi"]
    for kw in brand_keywords:
        if kw in check_domain:
            return "suspicious", "Possible look-alike domain mimicking an official brand or service."
            
    # 4. Check for high sequence similarity to trusted base domains
    for trusted in TRUSTED_DOMAINS:
        base_check = check_domain.split('.')[0]
        base_trusted = trusted.split('.')[0]
        ratio = difflib.SequenceMatcher(None, base_check, base_trusted).ratio()
        # High similarity on the base name
        if ratio >= 0.8:
            return "suspicious", f"Possible look-alike domain (high similarity to official site: {trusted})."
            
    # 5. Check if domain resembles trusted and uses a suspicious TLD
    # First check if the domain has moderate similarity to any trusted domain
    for trusted in TRUSTED_DOMAINS:
        full_ratio = difflib.SequenceMatcher(None, check_domain, trusted).ratio()
        if full_ratio >= 0.5:
            for tld in SUSPICIOUS_TLDS:
                if check_domain.endswith(tld):
                    return "suspicious", f"Suspicious TLD ({tld}) used with a domain resembling official services."
                    
    return "neutral", "Unknown domain, no specific spoofing patterns detected."

def analyze_urls_in_text(text: str) -> Dict:
    """
    Extracts and analyzes all URLs in the message text.
    """
    urls = extract_urls(text)
    url_details = []
    found_suspicious = False
    found_shortener = False
    
    for url in urls:
        domain = get_domain(url)
        status, reason = analyze_domain(domain)
        
        if status == "suspicious":
            found_suspicious = True
            if domain in SHORTENER_DOMAINS:
                found_shortener = True
                
        url_details.append({
            "url": url,
            "domain": domain,
            "status": status,
            "reason": reason
        })
        
    return {
        "found": len(urls) > 0,
        "urls": url_details,
        "found_suspicious": found_suspicious,
        "found_shortener": found_shortener
    }
