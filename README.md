# 🛡️ Scam Shield

### Check before you click.

Scam Shield is an AI-powered scam detection and verification platform designed to help users identify suspicious WhatsApp/SMS messages, links, files, and screenshots before interacting with them.

It focuses on real-world scam patterns such as fake e-Challan messages, malicious APK files, phishing links, banking scams, and urgency-based social engineering attacks.

---

## 🚨 Problem

Online scams are becoming increasingly convincing. Fraudsters often use WhatsApp and SMS to impersonate government departments, banks, delivery companies, and other trusted organizations.

Although awareness campaigns exist, users still face one important question when they receive a suspicious message:

> **"Is this particular message actually a scam?"**

Scam Shield acts as a real-time verification layer between receiving a suspicious message and taking an unsafe action.

---

## 💡 Solution

Scam Shield allows users to:

- Paste a suspicious WhatsApp/SMS message
- Upload a screenshot of a suspicious message
- Check suspicious URLs
- Detect malicious `.apk` file references
- Identify scam keywords and social-engineering patterns
- Detect suspicious or look-alike domains
- Identify shortened URLs
- Calculate an overall risk score
- View a detailed risk breakdown
- Get an AI-generated explanation
- Report suspicious scams

---

## 🔍 How Scam Shield Works

```text
User Input
    │
    ├── Text Message
    │
    ├── Screenshot
    │      ↓
    │     OCR
    │      ↓
    │   Extracted Text
    │
    └── Suspicious URL
             │
             ▼
       Detection Engine
             │
             ▼
        Risk Analysis
             │
             ▼
       Risk Breakdown
             │
             ▼
       RAG Knowledge Base
             │
             ▼
       LLM Explanation
             │
             ▼
       Safety Recommendation
