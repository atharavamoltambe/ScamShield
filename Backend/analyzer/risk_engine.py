from typing import Dict, List, Tuple, Optional

def calculate_risk(
    category: str,
    rules_analysis: Dict,
    url_analysis: Dict
) -> Tuple[int, str, float, List[str], List[str], str, List[Dict], Optional[Dict]]:
    """
    Evaluates the risk score, verdict, confidence, indicators, reasons, recommended action,
    and returns a granular risk breakdown and strongest warning sign.
    """
    # 1. Extract rule-based and URL-based indicators
    apk_detected = rules_analysis.get("apk_detected", False)
    urgency_detected = rules_analysis.get("urgency_detected", False)
    forwarded_urgency = rules_analysis.get("forwarded_urgency_combination", False)
    payment_detected = rules_analysis.get("payment_detected", False)
    credential_detected = rules_analysis.get("credential_detected", False)
    impersonation_detected = rules_analysis.get("impersonation_detected", False)
    strongest_cat = rules_analysis.get("strongest_category")
    
    urls_found = url_analysis.get("found", False)
    suspicious_urls = url_analysis.get("found_suspicious", False)
    shortener_urls = url_analysis.get("found_shortener", False)
    
    # Analyze domain list to see if look-alike exists
    lookalike_detected = False
    suspicious_domain_detected = False
    for u in url_analysis.get("urls", []):
        if u["status"] == "suspicious":
            if "look-alike" in u["reason"].lower():
                lookalike_detected = True
            elif "shortened" in u["reason"].lower():
                shortener_urls = True
            else:
                suspicious_domain_detected = True

    # 2. Compile granular risk breakdown items (Risk Groups)
    risk_breakdown = []
    
    # GROUP 1: FILE RISK
    if apk_detected:
        risk_breakdown.append({
            "factor": "Suspicious APK",
            "category": "file_risk",
            "points": 40,
            "severity": "high",
            "explanation": "Unexpected APK files sent through messaging apps can be used to distribute malicious applications."
        })
        
    # GROUP 2: LINK / DOMAIN RISK (Double-counting prevention: take the strongest triggered link risk)
    if urls_found:
        if lookalike_detected:
            risk_breakdown.append({
                "factor": "Look-alike domain",
                "category": "link_risk",
                "points": 30,
                "severity": "high",
                "explanation": "The link resembles an official website but does not use the trusted official domain."
            })
        elif suspicious_domain_detected:
            risk_breakdown.append({
                "factor": "Suspicious domain",
                "category": "link_risk",
                "points": 20,
                "severity": "high", # Treated as high/medium-high
                "explanation": "The link points to an unknown domain with suspicious patterns or an unusual top-level domain."
            })
        elif shortener_urls:
            risk_breakdown.append({
                "factor": "Shortened URL",
                "category": "link_risk",
                "points": 15,
                "severity": "medium",
                "explanation": "Shortened links hide the real destination website and make it harder to verify where the link leads."
            })

    # GROUP 3: URGENCY / SOCIAL ENGINEERING
    if urgency_detected:
        risk_breakdown.append({
            "factor": "Urgency language",
            "category": "urgency",
            "points": 15,
            "severity": "medium",
            "explanation": "Urgent deadlines can pressure users into acting before independently verifying the request."
        })

    # GROUP 4: PAYMENT RISK
    if payment_detected:
        risk_breakdown.append({
            "factor": "Suspicious payment language",
            "category": "payment",
            "points": 20,
            "severity": "medium", # Treated as medium/high
            "explanation": "Unexpected payment requests are a common component of phishing and social-engineering scams."
        })

    # GROUP 5: CREDENTIAL / ACCOUNT RISK
    if credential_detected:
        risk_breakdown.append({
            "factor": "Credential / Account risk",
            "category": "credential",
            "points": 30,
            "severity": "high",
            "explanation": "Requests for sensitive credentials or threats of account suspension are commonly used to pressure victims into revealing financial information."
        })

    # GROUP 6: IMPERSONATION RISK (Safeguard: Impersonation must be paired with other suspicious indicators)
    has_other_signals = apk_detected or urgency_detected or payment_detected or credential_detected or urls_found
    if impersonation_detected and has_other_signals:
        risk_breakdown.append({
            "factor": "Impersonation attempt",
            "category": "impersonation",
            "points": 15,
            "severity": "medium",
            "explanation": "Scammers often impersonate trusted organizations to make fraudulent requests appear legitimate."
        })

    # GROUP 7: SCAM LANGUAGE / KEYWORDS
    if strongest_cat and strongest_cat != "None":
        risk_breakdown.append({
            "factor": "Scam-related language",
            "category": "scam_language",
            "points": 7,
            "severity": "low",
            "explanation": "The message contains terminology commonly associated with known scam patterns."
        })

    # GROUP 8: FORWARDED + URGENCY
    if forwarded_urgency:
        risk_breakdown.append({
            "factor": "Forwarded urgency",
            "category": "forwarded_urgency",
            "points": 15,
            "severity": "medium", # Treated as medium/high
            "explanation": "Urgent messages that are forwarded through messaging platforms can spread rapidly, including through compromised or hijacked accounts."
        })

    # 3. Calculate Risk Score
    raw_score = sum(item["points"] for item in risk_breakdown)
    score = min(max(raw_score, 0), 100)

    # 4. Handle Official Advisory Bypass (Safety overrides)
    advisory_detected = rules_analysis.get("advisory_detected", False)
    if advisory_detected and not suspicious_urls and not lookalike_detected:
        score = 10  # Override to safe level

    # 5. Determine Verdict
    if score >= 60:
        verdict = "high_risk"
    elif score >= 30:
        verdict = "caution"
    else:
        verdict = "safe"

    # 6. Sort breakdown and identify strongest warning
    # Sort by points descending so highest indicators show first
    risk_breakdown.sort(key=lambda x: x["points"], reverse=True)

    strongest_warning = None
    if score >= 30 and risk_breakdown:
        strongest = risk_breakdown[0]
        
        # Humanize strongest warning message
        factor_name_lower = strongest["factor"].lower()
        if "apk" in factor_name_lower:
            warning_msg = "The APK reference is the strongest warning sign in this message."
        elif "domain" in factor_name_lower or "url" in factor_name_lower:
            warning_msg = "The suspicious link is the strongest warning sign in this message."
        elif "urgency" in factor_name_lower:
            warning_msg = "The urgency pressure is the strongest warning sign in this message."
        elif "payment" in factor_name_lower:
            warning_msg = "The request for payment is the strongest warning sign in this message."
        elif "credential" in factor_name_lower:
            warning_msg = "The request for sensitive account details is the strongest warning sign in this message."
        elif "impersonation" in factor_name_lower:
            warning_msg = "The impersonation of an official authority is the strongest warning sign in this message."
        else:
            warning_msg = f"The {factor_name_lower} is the strongest warning sign in this message."

        strongest_warning = {
            "factor": strongest["factor"],
            "points": strongest["points"],
            "message": warning_msg
        }

    # Clean risk breakdown if final score is safe (verdict == "safe" or score < 30)
    if verdict == "safe":
        risk_breakdown = []
        strongest_warning = None

    # 7. Compile Indicators and Reasons for backwards compatibility
    indicators = list(rules_analysis.get("indicators", []))
    reasons = list(rules_analysis.get("reasons", []))
    
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

    # Deduplicate lists
    indicators = list(dict.fromkeys(indicators))
    reasons = list(dict.fromkeys(reasons))

    # 8. Calculate Confidence (0.0 to 1.0)
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

    # 9. Determine Action Text
    if advisory_detected and not suspicious_urls and not lookalike_detected:
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

    return score, verdict, confidence, indicators, reasons, action, risk_breakdown, strongest_warning
