import os
from pathlib import Path
from typing import Dict, List

# Get base path for knowledge files
BASE_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = BASE_DIR / "data" / "knowledge"

def load_knowledge_chunks() -> Dict[str, List[str]]:
    """
    Loads text files from data/knowledge/ and splits them into paragraph chunks.
    Returns:
        Dict mapping category name to list of text chunks.
    """
    category_mapping = {
        "rto.txt": "RTO / e-Challan Scam",
        "banking.txt": "Banking / KYC Scam",
        "delivery.txt": "Delivery / Parcel Scam",
        "jobs.txt": "Job / Recruitment Scam"
    }
    
    knowledge_base = {}
    
    if not KNOWLEDGE_DIR.exists():
        return {}
        
    for filename, category_name in category_mapping.items():
        filepath = KNOWLEDGE_DIR / filename
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                # Split chunks by double newline
                paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
                knowledge_base[category_name] = paragraphs
            except Exception as e:
                # Fallback empty list for this category
                knowledge_base[category_name] = []
        else:
            knowledge_base[category_name] = []
            
    return knowledge_base
