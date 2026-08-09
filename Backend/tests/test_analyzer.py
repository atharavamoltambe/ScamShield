from fastapi.testclient import TestClient
import pytest
from app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "Scam Shield API"}

def test_rto_apk_scam():
    # 1. RTO APK scam
    payload = {
        "text": "TRAFFIC POLICE NOTICE. Your vehicle has an unpaid challan. Download RTO_Challan.apk to pay."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert data["score"] >= 60
    assert data["category"] == "RTO / e-Challan Scam"
    assert "APK file detected" in data["indicators"]
    assert any("apk" in reason.lower() for reason in data["reasons"])

def test_fake_challan_lookalike_domain():
    # 2. Fake challan + look-alike domain
    payload = {
        "text": "Your vehicle has a pending traffic violation fine. Click here to clear now: https://parivahaan.com/pay"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert data["score"] >= 60
    assert data["category"] == "RTO / e-Challan Scam"
    assert "Suspicious look-alike domain detected" in data["indicators"]

def test_banking_kyc_scam():
    # 3. Banking KYC scam
    payload = {
        "text": "URGENT: Your SBI bank account is blocked. Update KYC immediately or account will be suspended. http://sbi-verify.xyz/kyc"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert data["score"] >= 60
    assert data["category"] == "Banking / KYC Scam"
    assert "Urgency language detected" in data["indicators"]
    assert "Suspicious look-alike domain detected" in data["indicators"]

def test_delivery_scam():
    # 4. Delivery scam
    payload = {
        "text": "Your DHL parcel is held at the warehouse due to an incorrect address. Reschedule delivery here: http://cutt.ly/delivery-tracker"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "caution" or data["verdict"] == "high_risk"
    assert data["category"] == "Delivery / Parcel Scam"
    assert "Shortened URL detected" in data["indicators"]

def test_job_scam():
    # 5. Job scam
    payload = {
        "text": "Congratulations! Selected for a Work From Home job paying Rs 5000 daily. Secure your spot by paying a joining fee now."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "Job / Recruitment Scam"
    assert data["verdict"] in ["caution", "high_risk"]

def test_shortened_url():
    # 6. Shortened URL
    payload = {
        "text": "Click this link now: bit.ly/some-link"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "Shortened URL detected" in data["indicators"]
    assert data["verdict"] == "caution"

def test_forwarded_urgency():
    # 7. Forwarded + urgency
    payload = {
        "text": "Forwarded. Act immediately to receive your gift, today only!"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "Forwarded message combined with urgency" in data["indicators"]
    assert data["verdict"] == "caution"

def test_normal_safe_message():
    # 8. Normal safe message
    payload = {
        "text": "Your order has been delivered successfully. Thank you for shopping with us."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert data["score"] < 30
    assert not data["indicators"]

def test_empty_input():
    # 9. Empty input
    # Empty string
    response = client.post("/api/check", json={"text": ""})
    assert response.status_code == 400
    assert response.json() == {"error": "Message text is required."}

    # Whitespace string
    response = client.post("/api/check", json={"text": "   "})
    assert response.status_code == 400
    assert response.json() == {"error": "Message text is required."}

    # Missing text key
    response = client.post("/api/check", json={})
    assert response.status_code == 400
    assert response.json() == {"error": "Message text is required."}

def test_multiple_scam_indicators():
    # 10. Multiple scam indicators
    payload = {
        "text": "TRAFFIC POLICE NOTICE. Your vehicle has an unpaid challan. Pay within 24 hours to avoid further action. Download RTO_Challan.apk or click https://parivahaan.com/pay"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert data["score"] >= 90
    assert "APK file detected" in data["indicators"]
    assert "Urgency language detected" in data["indicators"]
    assert "Suspicious look-alike domain detected" in data["indicators"]
    assert len(data["rag_context"]) > 0

def test_reports_api():
    # Test reporting endpoint
    report_payload = {
        "text": "Urgent: call bank immediately",
        "notes": "Spam call follow-up SMS"
    }
    response = client.post("/api/report", json=report_payload)
    assert response.status_code == 200
    assert response.json() == {"status": "reported"}

    # Fetch reports list
    response = client.get("/api/reports")
    assert response.status_code == 200
    reports = response.json()
    assert len(reports) >= 4  # 3 pre-seeded + 1 newly reported
    assert reports[0]["text"] == "Urgent: call bank immediately"
    assert reports[0]["notes"] == "Spam call follow-up SMS"
    assert "timestamp" in reports[0]

def test_official_advisory_safe():
    # Advisory from RBI without links should be flagged safe
    payload = {
        "text": "Reserve Bank of India (RBI) scam alert: Beware of fake SMS messages asking to download RTO_Challan.apk. Issued in public interest."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert data["score"] == 10
    assert "Official safety advisory detected" in data["indicators"]
    assert "safety action" in data["action"].lower()

def test_official_advisory_spoofed_high_risk():
    # Spoofed advisory containing a suspicious link should remain high risk
    payload = {
        "text": "rbi advisory warning: click http://fake-rbi.xyz to verify your UPI account immediately."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert "Official safety advisory detected" in data["indicators"]
    assert "Suspicious look-alike domain detected" in data["indicators"] or "Suspicious domain detected" in data["indicators"]

def test_risk_breakdown_challan_apk():
    # Test 1 — Fake challan APK
    payload = {
        "text": "Traffic Police Notice. Your vehicle has an unpaid challan. Pay within 24 hours. Download RTO_Challan.apk and visit https://parivahaan.com/pay"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    # Points expected: APK (40) + Look-alike domain (30) + Urgency (15) + Scam language (7) + Payment (20) + Impersonation (15) = 127 -> Capped at 100
    assert data["score"] == 100
    
    breakdown = data["risk_breakdown"]
    categories = [item["category"] for item in breakdown]
    assert "file_risk" in categories
    assert "link_risk" in categories
    assert "urgency" in categories
    assert "scam_language" in categories
    
    # Verify strongest warning
    assert data["strongest_warning"]["factor"] == "Suspicious APK"
    assert data["strongest_warning"]["points"] == 40

def test_risk_breakdown_banking_scam():
    # Test 2 — Banking scam
    payload = {
        "text": "Your KYC has expired. Your bank account will be blocked within 24 hours. Click now to verify your account."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "caution"
    # Points expected: Urgency (15) + Credential risk (30) + Scam language (7) = 52
    assert data["score"] == 52

def test_risk_breakdown_shortener():
    # Test 3 — Shortened URL
    payload = {
        "text": "Your reward is waiting. Click now: https://bit.ly/example"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Points expected: Shortened URL (15) + Urgency (15) = 30
    assert data["score"] == 30
    assert any(item["category"] == "link_risk" and item["factor"] == "Shortened URL" for item in data["risk_breakdown"])

def test_risk_breakdown_forwarded_urgency():
    # Test 4 — Forwarded urgency
    payload = {
        "text": "Forwarded: Your account will be blocked within 24 hours. Verify immediately."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    # Points expected: Urgency (15) + Forwarded urgency (15) + Credential risk (30) = 60
    assert data["score"] == 60

def test_risk_breakdown_safe():
    # Test 5 — Safe message
    payload = {
        "text": "Your order has been delivered successfully. Thank you for shopping with us."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert data["score"] == 0
    # Safe message should clear risk breakdown array
    assert data["risk_breakdown"] == []
    assert data["strongest_warning"] is None

def test_risk_breakdown_multiple_urgency():
    # Test 6 — Multiple urgency keywords
    payload = {
        "text": "Pay immediately. Click now. Final warning. You have 24 hours."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Points expected: Urgency (15) + Payment risk (20) = 35
    assert data["score"] == 35
    # Urgency must be counted exactly once
    urgency_items = [item for item in data["risk_breakdown"] if item["category"] == "urgency"]
    assert len(urgency_items) == 1

def test_risk_breakdown_multiple_keywords():
    # Test 7 — Multiple scam keywords
    payload = {
        "text": "challan e-challan pending fine mParivahan."
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Points expected: Scam language (7) + Payment risk (20) [fine] = 27 (Safe score)
    assert data["score"] < 30
    assert data["verdict"] == "safe"

def test_risk_breakdown_legitimate_gov_domain():
    # Test 8 — Legitimate government domain
    payload = {
        "text": "Check your challan status at https://echallan.parivahan.gov.in"
    }
    response = client.post("/api/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Legitimate URL must not count positive points
    # Points expected: Scam language (7) [challan] + Payment risk (20) [challan] = 27 (Safe score)
    assert data["score"] < 30
    assert data["verdict"] == "safe"

