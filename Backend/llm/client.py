import os
import re
import json
import logging
import httpx
from typing import Dict, Optional, Tuple

logger = logging.getLogger("scam_shield_llm")

def clean_json_response(text: str) -> str:
    """
    Cleans markdown code blocks (```json ... ```) from the LLM text output.
    """
    cleaned = text.strip()
    # Check for ```json ... ```
    json_match = re.search(r'```json\s*(.*?)\s*```', cleaned, re.DOTALL)
    if json_match:
        return json_match.group(1).strip()
    # Check for ``` ... ```
    general_match = re.search(r'```\s*(.*?)\s*```', cleaned, re.DOTALL)
    if general_match:
        return general_match.group(1).strip()
    return cleaned

def get_llm_config() -> Tuple[bool, str, str, str]:
    """
    Fetches LLM configuration from environment variables.
    Returns:
        (enabled, api_key, model, provider)
    """
    # Check if LLM is explicitly enabled (defaults to false for safety)
    enabled_str = os.environ.get("LLM_ENABLED", "false").lower()
    enabled = enabled_str == "true"
    
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    provider = os.environ.get("LLM_PROVIDER", "").strip().lower()
    
    # Auto-detect provider if not explicitly configured
    if not provider:
        if api_key.startswith("AIzaSy"):
            provider = "gemini"
        elif api_key.startswith("sk-"):
            provider = "openai"
        else:
            provider = "gemini"  # Default fallback provider
            
    # Model defaults
    default_model = "gemini-3.5-flash" if provider == "gemini" else "gpt-4o-mini"
    model = os.environ.get("LLM_MODEL", default_model).strip()
    
    return enabled, api_key, model, provider

def call_llm_api(prompt: str, system_instruction: Optional[str] = None) -> str:
    """
    Sends the prompt to the configured LLM API using httpx synchronously.
    Enforces a strict 5-second timeout.
    """
    enabled, api_key, model, provider = get_llm_config()
    
    if not enabled:
        raise ValueError("LLM is disabled via LLM_ENABLED configuration.")
    if not api_key:
        raise ValueError("LLM_API_KEY environment variable is missing.")
        
    timeout = 10.0  # Strict timeout limit
    
    if provider == "gemini":
        # Google Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        
        # In Gemini v1beta, systemInstruction can be passed inside the config.
        # Let's combine system instruction and user prompt to be safe and compatible with all models.
        combined_text = prompt
        if system_instruction:
            combined_text = f"System Instruction: {system_instruction}\n\nUser Data and Prompt:\n{prompt}"
            
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": combined_text}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "thinkingConfig": {
                    "thinkingBudget": 0
                }
            }
        }
        
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()
            
            # Extract text candidate
            try:
                text_output = response_data["candidates"][0]["content"]["parts"][0]["text"]
                return text_output
            except (KeyError, IndexError) as e:
                logger.error(f"Malformed Gemini API response: {response_data}")
                raise ValueError("Failed to extract content from Gemini API response.")
                
    elif provider == "openai":
        # OpenAI API compatible layout
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "messages": messages,
            "response_format": {"type": "json_object"}
        }
        
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            
            try:
                text_output = response_data["choices"][0]["message"]["content"]
                return text_output
            except (KeyError, IndexError) as e:
                logger.error(f"Malformed OpenAI API response: {response_data}")
                raise ValueError("Failed to extract content from OpenAI API response.")
    else:
        raise ValueError(f"Unsupported LLM provider configured: {provider}")
