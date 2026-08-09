import re
from typing import List, Dict
from rag.knowledge_base import load_knowledge_chunks

def tokenize(text: str) -> set:
    """
    Splits text into a set of lowercased alphanumeric words of length >= 3.
    """
    return set(re.findall(r'\b[a-zA-Z0-9]{3,}\b', text.lower()))

def retrieve_context(
    message: str,
    detected_category: str,
    indicators: List[str],
    max_chunks: int = 3
) -> Dict:
    """
    Tokenizes input, computes overlap scoring with knowledge base chunks,
    applies category boosting, and returns the top relevant chunks.
    """
    kb = load_knowledge_chunks()
    
    message_tokens = tokenize(message)
    for indicator in indicators:
        message_tokens.update(tokenize(indicator))
        
    scored_chunks = []
    
    for category, chunks in kb.items():
        # Apply category matching boost
        is_matching_category = (category == detected_category)
        
        for chunk in chunks:
            chunk_tokens = tokenize(chunk)
            overlap = len(message_tokens.intersection(chunk_tokens))
            
            # Boost score if category matches
            category_boost = 6.0 if is_matching_category else 0.0
            
            # Simple retrieval scoring
            score = overlap + category_boost
            
            if overlap > 0 or is_matching_category:
                scored_chunks.append((score, chunk))
                
    # Sort by score descending
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    
    # Retrieve unique chunks
    seen = set()
    retrieved = []
    for score, chunk in scored_chunks:
        if chunk not in seen:
            seen.add(chunk)
            retrieved.append(chunk)
        if len(retrieved) >= max_chunks:
            break
            
    # Fallback to category base chunks if retrieval list is empty
    if not retrieved and detected_category in kb and kb[detected_category]:
        retrieved = kb[detected_category][:2]
        
    return {
        "category": detected_category or "General Phishing",
        "context": retrieved
    }
