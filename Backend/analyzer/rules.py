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
    "pay now", "verify immediately", "expires today"
]

# Define suspicious payment-related keywords
PAYMENT_KEYWORDS = [
    "joining fee", "registration fee", "interview fee", "processing fee", 
    "placement fee", "customs fee", "delivery fee", "pay now", "unpaid challan", 
    "traffic fine", "vehicle fine", "pending fine", "road tax", "unpaid", 
    "payment", "payout", "fee"
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

def analyze_text_rules(text: str) -> Dict:
    """
    Run rules-based detection on the input text.
    Returns detected categories, APK status, urgency status, and indicators.
    """
    text_lower = text.lower()
    
    # 1. Category keyword matching
    category_scores = {}
    for cat, keywords in CATEGORIES.items():
        score = 0
        for kw in keywords:
            # Match keywords as sub-strings
            if kw in text_lower:
                score += 1
        category_scores[cat] = score
    
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
    urgency_detected = False
    matched_urgency_words = []
    for kw in URGENCY_KEYWORDS:
        if kw in text_lower:
            urgency_detected = True
            matched_urgency_words.append(kw)

    # 4. Forwarded + Urgency Detection
    forwarded_detected = "forwarded" in text_lower
    forwarded_urgency_combination = forwarded_detected and urgency_detected

    # 5. Suspicious Payment Language Detection
    payment_detected = False
    matched_payment_words = []
    for kw in PAYMENT_KEYWORDS:
        if kw in text_lower:
            payment_detected = True
            matched_payment_words.append(kw)

    # 6. Advisory / Awareness Detection
    advisory_detected = False
    if any(kw in text_lower for kw in ADVISORY_KEYWORDS) and any(auth in text_lower for auth in AUTHORITY_KEYWORDS):
        advisory_detected = True

    # Compile indicators and explanations
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

    if advisory_detected:
        indicators.append("Official safety advisory detected")
        reasons.append("The message appears to be an official warning or public safety advisory raising awareness about scam vectors.")

  # Return results including advisory indicator
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
        "indicators": indicators,
        "reasons": reasons
    }
