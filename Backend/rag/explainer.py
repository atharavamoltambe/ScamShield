import os
from typing import List, Dict

def generate_explanation(
    message: str,
    rules_analysis: Dict,
    url_analysis: Dict,
    rag_context: List[str]
) -> List[str]:
    """
    Constructs a list of natural explanation reasons based on rules, URL analysis, and RAG context.
    Acts as a deterministic fallback. If an LLM provider (e.g. Gemini, OpenAI) is configured 
    in environment variables later, it can easily replace this implementation.
    """
    # For MVP: Deterministic fallback explanation generator
    reasons = []
    
    category = rules_analysis.get("strongest_category")
    apk_detected = rules_analysis.get("apk_detected", False)
    urgency_detected = rules_analysis.get("urgency_detected", False)
    forwarded_urgency = rules_analysis.get("forwarded_urgency_combination", False)
    
    # 1. Base category warning
    if category:
        reasons.append(f"This message matches patterns associated with {category}s.")
    else:
        if apk_detected or urgency_detected or url_analysis.get("found_suspicious", False):
            reasons.append("This message contains suspicious indicators, suggesting a general phishing or scam attempt.")
            
    # 2. APK specific warning
    if apk_detected:
        reasons.append("The APK file reference is highly suspicious. Unexpected installable applications sent via messaging apps are a major security warning sign and frequently install malware.")
        
    # 3. URL analysis warning
    if url_analysis.get("found", False):
        for u in url_analysis.get("urls", []):
            if u["status"] == "suspicious":
                if "shortened" in u["reason"].lower():
                    reasons.append("The message contains a shortened URL which hides the actual destination address, making verification difficult.")
                elif "look-alike" in u["reason"].lower():
                    reasons.append(f"The link '{u['url']}' is highly suspicious because it mimics a trusted official domain but is not registered on the official whitelist.")
                else:
                    reasons.append(f"The link leads to '{u['domain']}', which is not a trusted domain and shows scam/phishing characteristics.")
            elif u["status"] == "neutral":
                reasons.append(f"The message references '{u['url']}'. While not flagrantly malicious, unknown external links should be approached with caution.")

    # 4. Urgency and Social Engineering warning
    if forwarded_urgency:
        reasons.append("The message is a forwarded message containing urgency language. Attackers frequently use forwarded messages to scale social engineering campaigns quickly.")
    elif urgency_detected:
        reasons.append("The message attempts to create pressure or urgency (e.g., demanding action immediately or within a deadline), which is a classic psychological trigger used to prevent careful verification.")

    # 5. Bring in key point from RAG context
    if rag_context:
        # Find a sentence mentioning "verify" or "official" or similar advice
        added_rag = False
        for chunk in rag_context:
            sentences = [s.strip() for s in chunk.split('.') if s.strip()]
            for s in sentences:
                if any(k in s.lower() for k in ["verify", "official", "never", "always"]):
                    reasons.append(f"Official guidance: {s}.")
                    added_rag = True
                    break
            if added_rag:
                break
        
        # Fallback if no matching sentence found
        if not added_rag and rag_context:
            first_chunk_sentences = [s.strip() for s in rag_context[0].split('.') if s.strip()]
            if first_chunk_sentences:
                reasons.append(f"Additional context: {first_chunk_sentences[0]}.")
                    
    # Deduplicate reasons (case-insensitive check)
    deduped = []
    seen = set()
    for r in reasons:
        if r.lower() not in seen:
            seen.add(r.lower())
            deduped.append(r)
            
    return deduped
