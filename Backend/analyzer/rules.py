import re
from typing import Dict, List, Tuple

# Define scam categories and their respective keywords (case-insensitive)
CATEGORIES: Dict[str, List[str]] = {
    "RTO / e-Challan Scam": [
        "challan", "e-challan", "echallan", "mparivahan", "parivahan", "rto", 
        "traffic fine", "vehicle fine", "pending fine", "unpaid challan", 
        "traffic police", "vehicle number", "road tax", "traffic violation"
    ],
    "Banking / KYC Scam": [
        "kyc", "account blocked", "account suspended", "bank account", 
        "verify account", "update kyc", "otp", "debit card", "credit card", 
        "net banking", "banking", "transaction failed", "account verification", 
        "beneficiary", "banking password", "upi", "upi blocked", "upi verification"
    ],
    "Delivery / Parcel Scam": [
        "parcel", "package", "shipment", "courier", "delivery", "customs", 
        "customs fee", "delivery fee", "shipping", "held at customs", 
        "address verification", "tracking", "delivery attempt", "warehouse"
    ],
    "Job / Recruitment Scam": [
        "job offer", "selected for job", "registration fee", "interview fee", 
        "processing fee", "recruitment", "work from home", "salary", 
        "vacancy", "employment", "hiring", "joining fee", "job confirmation", 
        "placement fee"
    ]
}

URGENCY_KEYWORDS = [
    "pay immediately", "click now", "act now", "within 24 hours", "today only", 
    "account will be blocked", "account blocked", "immediate action", "urgent", 
    "final warning", "last chance", "avoid penalty", "avoid legal action", 
    "pay now", "verify immediately", "expires today", "immediately", "urgently",
    "blocked", "suspended", "expired", "expiring", "action required", "now"
]

# Define suspicious payment-related keywords
PAYMENT_KEYWORDS = [
    "joining fee", "registration fee", "interview fee", "processing fee", 
    "placement fee", "customs fee", "delivery fee", "pay now", "unpaid challan", 
    "traffic fine", "vehicle fine", "pending fine", "road tax", "unpaid", 
    "payment", "payout", "fee", "pay", "fine", "charge", "transfer", "send money"
]

ADVISORY_KEYWORDS = [
    "beware", "warning", "scam alert", "public interest", "fake message", 
    "advisory", "warns", "alert", "don't install", "do not download", "don't click",
    "awareness", "public awareness"
]

AUTHORITY_KEYWORDS = [
    "reserve bank", "rbi", "police", "government", "cyber cell", "cybercrime",
    "pib", "authority", "official warning"
]

CREDENTIAL_KEYWORDS = [
    "otp", "password", "pin", "cvv", "kyc", "credential", 
    "blocked", "suspended", "verify account", "verify credentials", "verify kyc",
    "bank account", "login", "username"
]

IMPERSONATION_KEYWORDS = [
    "police", "rto", "rbi", "reserve bank", "customs", "tax department", 
    "courier", "dhl", "speed post", "official authority"
]

def get_matched_keywords(text_lower: str, keywords: List[str]) -> List[str]:
    """
    Finds keywords in text_lower using word boundary checks for short words (<=3 chars)
    to prevent false positives like matching 'pin' in 'shopping' or 'pending'.
    """
    matched = []
    for kw in keywords:
        if len(kw) <= 3:
            pattern = r'\b' + re.escape(kw) + r'\b'
            if re.search(pattern, text_lower):
                matched.append(kw)
        else:
            if kw in text_lower:
                matched.append(kw)
    return matched

def analyze_text_rules(text: str) -> Dict:
    """
    Run rules-based detection on the input text.
    Returns detected categories, APK status, urgency status, and indicators.
    """
    text_lower = text.lower()
    
    # 1. Category keyword matching
    category_scores = {}
    for cat, keywords in CATEGORIES.items():
        matched = get_matched_keywords(text_lower, keywords)
        category_scores[cat] = len(matched)
    
    # Select the category with the highest evidence
    strongest_cat = None
    max_score = 0
    for cat, score in category_scores.items():
        if score > max_score:
            max_score = score
            strongest_cat = cat
            
    # 2. APK Detection
    # Detect .apk extension or the word 'apk' explicitly in installation context
    apk_detected = False
    apk_pattern = r'\b\w+\.apk\b|\binstall\s+apk\b|\bdownload\s+apk\b'
    if ".apk" in text_lower or re.search(apk_pattern, text_lower):
        apk_detected = True

    # 3. Urgency Detection
    matched_urgency_words = get_matched_keywords(text_lower, URGENCY_KEYWORDS)
    urgency_detected = len(matched_urgency_words) > 0

    # 4. Forwarded + Urgency Detection
    forwarded_detected = "forwarded" in text_lower
    forwarded_urgency_combination = forwarded_detected and urgency_detected

    # 5. Suspicious Payment Language Detection
    matched_payment_words = get_matched_keywords(text_lower, PAYMENT_KEYWORDS)
    payment_detected = len(matched_payment_words) > 0

    # 6. Advisory / Awareness Detection
    matched_advisories = get_matched_keywords(text_lower, ADVISORY_KEYWORDS)
    matched_authorities = get_matched_keywords(text_lower, AUTHORITY_KEYWORDS)
    advisory_detected = len(matched_advisories) > 0 and len(matched_authorities) > 0

    # 7. Credential / Account Detection
    matched_credentials = get_matched_keywords(text_lower, CREDENTIAL_KEYWORDS)
    credential_detected = len(matched_credentials) > 0 or ("verify" in text_lower and "account" in text_lower)

    # 8. Impersonation Detection
    matched_impersonations = get_matched_keywords(text_lower, IMPERSONATION_KEYWORDS)
    impersonation_detected = len(matched_impersonations) > 0

    # Compile indicators and explanations for retro-compatibility
    indicators = []
    reasons = []

    if apk_detected:
        indicators.append("APK file detected")
        reasons.append("This message references an APK file. Unexpected installable apps received through WhatsApp or SMS are a major security warning sign.")

    if strongest_cat:
        indicators.append(f"{strongest_cat} keywords detected")
        reasons.append(f"The message contains keywords highly associated with {strongest_cat.replace(' Scam', 's')}.")

    if urgency_detected:
        indicators.append("Urgency language detected")
        reasons.append(f"The message creates high pressure/urgency with terms like: {', '.join(matched_urgency_words[:3])}.")

    if forwarded_urgency_combination:
        indicators.append("Forwarded message combined with urgency")
        reasons.append("Forwarded message combined with urgency can indicate social engineering, particularly when the message asks the recipient to click, download, or pay.")

    if payment_detected:
        indicators.append("Suspicious payment language detected")
        reasons.append(f"The message references a payment request or fee: '{', '.join(matched_payment_words[:2])}'.")

    if credential_detected:
        indicators.append("Credential / Account risk detected")
        reasons.append("The message targets sensitive credentials (like OTP/passwords) or threatens account suspension.")

    if impersonation_detected:
        indicators.append("Impersonation attempt detected")
        reasons.append("The message uses wording mimicking a government agency, police force, bank, or other official authority.")

    if advisory_detected:
        indicators.append("Official safety advisory detected")
        reasons.append("The message appears to be an official warning or public safety advisory raising awareness about scam vectors.")

    return {
        "strongest_category": strongest_cat,
        "category_scores": category_scores,
        "apk_detected": apk_detected,
        "urgency_detected": urgency_detected,
        "matched_urgency": matched_urgency_words,
        "forwarded_detected": forwarded_detected,
        "forwarded_urgency_combination": forwarded_urgency_combination,
        "payment_detected": payment_detected,
        "advisory_detected": advisory_detected,
        "credential_detected": credential_detected,
        "impersonation_detected": impersonation_detected,
        "indicators": indicators,
        "reasons": reasons
    }
