from typing import Dict, List, Tuple

def calculate_risk(
    category: str,
    rules_analysis: Dict,
    url_analysis: Dict
) -> Tuple[int, str, float, List[str], List[str], str]:
    """
    Evaluates the risk score, verdict, confidence, indicators, reasons, and recommended action.
    Returns:
        (score, verdict, confidence, indicators, reasons, action)
    """
    score = 0
    indicators = list(rules_analysis.get("indicators", []))
    reasons = list(rules_analysis.get("reasons", []))
    
    apk_detected = rules_analysis.get("apk_detected", False)
    urgency_detected = rules_analysis.get("urgency_detected", False)
    forwarded_urgency = rules_analysis.get("forwarded_urgency_combination", False)
    payment_detected = rules_analysis.get("payment_detected", False)
    
    urls_found = url_analysis.get("found", False)
    suspicious_urls = url_analysis.get("found_suspicious", False)
    shortener_urls = url_analysis.get("found_shortener", False)
    
    # Analyze domain list to see if look-alike exists
    lookalike_detected = False
    for u in url_analysis.get("urls", []):
        if u["status"] == "suspicious" and "look-alike" in u["reason"].lower():
            lookalike_detected = True
            
    # Compile URL indicators and reasons
    if urls_found:
        for u in url_analysis.get("urls", []):
            if u["status"] == "suspicious":
                if "shortened" in u["reason"].lower():
                    indicators.append("Shortened URL detected")
                    reasons.append("Shortened links hide the real destination website and make it harder to verify where the link leads.")
                elif "look-alike" in u["reason"].lower():
                    indicators.append("Suspicious look-alike domain detected")
                    reasons.append(f"The link '{u['url']}' appears to mimic an official domain but does not match the trusted official domain.")
                else:
                    indicators.append("Suspicious domain detected")
                    reasons.append(f"The domain '{u['domain']}' has suspicious patterns or unusual top-level domain.")

    # Deduplicate indicators & reasons
    indicators = list(dict.fromkeys(indicators))
    reasons = list(dict.fromkeys(reasons))

    # Scoring Logic
    # 1. Very High Severity Combinations
    if apk_detected and (category in ["RTO / e-Challan Scam", "Banking / KYC Scam"] or suspicious_urls):
        score = 95
    elif apk_detected and urls_found:
        score = 90
    elif lookalike_detected and urgency_detected:
        score = 85
    # 2. High Severity Indicators
    elif apk_detected:
        score = 75
    elif lookalike_detected:
        score = 70
    elif suspicious_urls and category in ["Banking / KYC Scam", "RTO / e-Challan Scam"]:
        score = 75
    elif suspicious_urls and urgency_detected:
        score = 65
    # 3. Medium Severity Indicators
    elif shortener_urls and urgency_detected:
        score = 55
    elif forwarded_urgency and urls_found:
        score = 50
    elif payment_detected and category != "None" and category is not None:
        score = 45
    elif urgency_detected and category != "None" and category is not None:
        score = 45
    elif shortener_urls:
        score = 35
    elif payment_detected:
        score = 30
    elif forwarded_urgency:
        score = 30
    elif urgency_detected:
        score = 25
    # 4. Low Severity (Keywords only)
    elif category != "None" and category is not None:
        # Just matching keywords without other vectors
        score = 15
    else:
        score = 0


    # Ensure score doesn't exceed 100
    score = min(max(score, 0), 100)

    # Override score for safe official advisories (no suspicious URLs)
    advisory_detected = rules_analysis.get("advisory_detected", False)
    if advisory_detected and not suspicious_urls:
        score = 10  # Downgrade to safe level

    # Determine Verdict
    if score >= 60:
        verdict = "high_risk"
    elif score >= 30:
        verdict = "caution"
    else:
        verdict = "safe"

    # Calculate Confidence (0.0 to 1.0)
    if score == 0:
        confidence = 0.95
    elif score >= 90:
        confidence = 0.92
    else:
        base_conf = 0.5
        indicator_factor = min(len(indicators) * 0.15, 0.3)
        category_factor = 0.15 if (category and category != "General Scam / Phishing") else 0.0
        confidence = round(base_conf + indicator_factor + category_factor, 2)
        confidence = min(max(confidence, 0.1), 0.95)

    # Determine Action Text
    if advisory_detected and not suspicious_urls:
        action = "This appears to be an official public safety advisory warning about scam patterns. Be aware of the warning details, but you do not need to take any safety action."
    elif verdict == "high_risk":
        if category == "RTO / e-Challan Scam":
            action = "Do not open this file or click this link. Delete the message. Verify any challan only at echallan.parivahan.gov.in. If you already installed the file: disconnect from the internet, uninstall the app, change your banking/UPI passwords, and call 1930 (National Cyber Fraud Helpline)."
        elif category == "Banking / KYC Scam":
            action = "Do not click this link or share any OTP/credentials. Delete the message. Contact your bank directly through official numbers. If you entered details: change banking passwords immediately, block your cards, and call 1930 (National Cyber Fraud Helpline)."
        elif category == "Delivery / Parcel Scam":
            action = "Do not click this link or pay any fee. Track your package only on the official courier website. If you made a payment: contact your bank to freeze your card and report to 1930 (National Cyber Fraud Helpline)."
        elif category == "Job / Recruitment Scam":
            action = "Do not pay any upfront fees. Genuine employers never charge job seekers. Verify the job opening directly on the company's official career portal."
        else:
            action = "Do not open this file or click this link. Delete the message. Verify independently through official channels."
    elif verdict == "caution":
        action = "Be careful — this has some suspicious signs. Verify independently before clicking or paying anything."
    else:
        action = "No major red flags detected, but always verify unexpected payment requests through official channels."

    return score, verdict, confidence, indicators, reasons, action
