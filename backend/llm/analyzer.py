import os
import json
import sqlite3
import hashlib
import requests
from typing import Dict, Any
from dotenv import load_dotenv

try:
    import redis
except ImportError:
    redis = None

load_dotenv()

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1" # Standard 8B model available on Ollama

def get_redis_client():
    redis_url = os.environ.get("REDIS_URL")
    if redis_url and redis:
        try:
            return redis.from_url(redis_url)
        except Exception as e:
            print(f"Failed to connect to Redis: {e}")
    return None

def get_cache_db():
    db_path = os.path.join(os.path.dirname(__file__), "..", "llm_cache.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigations (
            hash TEXT PRIMARY KEY,
            result_json TEXT
        )
    ''')
    conn.commit()
    return conn

def generate_finding_hash(finding: Dict[str, Any], context: str) -> str:
    """
    Generates a unique hash for the vulnerability and its RAG context 
    to avoid redundant LLM calls.
    """
    # Use file, line, rule id, snippet and retrieved context
    raw = f"{finding.get('file')}:{finding.get('line')}:{finding.get('id')}:{finding.get('snippet')}:{context}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def construct_prompt(finding: Dict[str, Any], context: str) -> str:
    return f"""You are an expert Application Security Engineer. Review the following static analysis finding and the provided security documentation.
Determine if this finding is genuinely exploitable in the given code snippet, provide a confidence level, and recommend a cited fix.

SECURITY DOCUMENTATION (OWASP/CWE):
{context}

STATIC ANALYSIS FINDING:
Rule ID: {finding.get('id')}
Message: {finding.get('message')}
File: {finding.get('file')}
Line: {finding.get('line')}
Code Snippet:
```
{finding.get('snippet')}
```

Provide your analysis strictly in the following JSON format without any markdown blocks or extra text:
{{
    "explanation": "A plain-English explanation of whether this is genuinely exploitable here based on the code.",
    "confidence": "High, Medium, or Low",
    "fix": "A cited fix recommendation referencing the provided security documentation."
}}
"""

def query_groq_fallback(prompt: str) -> Dict[str, str]:
    """
    Fallback to Groq API if local Ollama fails.
    Requires GROQ_API_KEY environment variable.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {
            "explanation": "LLM Analysis failed. Ollama is not running and GROQ_API_KEY is not set.",
            "confidence": "Low",
            "fix": "N/A"
        }

    print("Ollama failed. Falling back to Groq API...")
    try:
        from groq import Groq
        
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
              {
                "role": "user",
                "content": prompt
              }
            ],
            temperature=0.2,
            max_completion_tokens=2048,
            stream=False,
            response_format={"type": "json_object"}
        )
        
        result_text = completion.choices[0].message.content.strip()
        
        # Strip markdown code blocks if the model wrapped the JSON (just in case)
        if result_text.startswith("```json"):
            result_text = result_text.replace("```json", "", 1).rstrip("`").strip()
        elif result_text.startswith("```"):
            result_text = result_text.replace("```", "", 1).rstrip("`").strip()
            
        return json.loads(result_text)
    except Exception as e:
        print(f"Error querying Groq API: {e}")
        return {
            "explanation": "LLM Analysis failed. Both Ollama and Groq fallback failed.",
            "confidence": "Low",
            "fix": "N/A"
        }

def query_llm(prompt: str) -> Dict[str, str]:
    """
    Calls the local Ollama API to run the LLM inference.
    Falls back to Grok API if Ollama is unreachable.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json" # Ensures strict JSON output if supported by model
    }
    
    try:
        # Fast timeout for Ollama to quickly fallback if it's completely down
        response = requests.post(OLLAMA_URL, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # Parse the JSON string returned by the model
        result_text = data.get("response", "{}").strip()
        return json.loads(result_text)
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Ollama connection error: {e}")
        return query_groq_fallback(prompt)

def analyze_finding(finding: Dict[str, Any], rag_context: str) -> Dict[str, str]:
    """
    Main entry point for the LLM Investigation Pipeline.
    Checks the hybrid Redis/SQLite cache first; if miss, queries Ollama.
    """
    finding_hash = generate_finding_hash(finding, rag_context)
    
    # 1. Try Redis Cache
    redis_client = get_redis_client()
    if redis_client:
        try:
            cached_result = redis_client.get(finding_hash)
            if cached_result:
                print(f"Redis cache hit for finding {finding.get('id')}")
                return json.loads(cached_result)
        except Exception as e:
            print(f"Redis get error: {e}")
    
    # 2. Try SQLite Cache Fallback
    conn = get_cache_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT result_json FROM investigations WHERE hash = ?', (finding_hash,))
    row = cursor.fetchone()
    
    if row:
        print(f"SQLite cache hit for finding {finding.get('id')} at {finding.get('file')}:{finding.get('line')}")
        # Backfill Redis if it's running but didn't have the key
        if redis_client:
            try:
                redis_client.set(finding_hash, row[0])
            except Exception:
                pass
        conn.close()
        return json.loads(row[0])
        
    print(f"Cache miss. Running LangGraph multi-agent investigation for {finding.get('id')}...")
    
    try:
        from llm.graph import app
        
        initial_state = {
            "finding": finding,
            "rag_context": rag_context,
            "analysis": "",
            "confidence": "",
            "fix_recommendation": ""
        }
        
        # Invoke the LangGraph orchestration
        final_state = app.invoke(initial_state)
        
        analysis_result = {
            "explanation": final_state.get("analysis", "Analysis failed"),
            "confidence": final_state.get("confidence", "Low"),
            "fix": final_state.get("fix_recommendation", "N/A")
        }
    except Exception as e:
        print(f"LangGraph execution error: {e}")
        analysis_result = {
            "explanation": f"LLM Analysis failed during multi-agent execution: {e}",
            "confidence": "Low",
            "fix": "N/A"
        }
    
    # Save to cache only if it didn't fail
    if "failed" not in analysis_result.get("explanation", "").lower():
        result_json_str = json.dumps(analysis_result)
        
        # Save to Redis
        if redis_client:
            try:
                redis_client.set(finding_hash, result_json_str)
            except Exception as e:
                print(f"Redis set error: {e}")
                
        # Save to SQLite
        cursor.execute('INSERT OR IGNORE INTO investigations (hash, result_json) VALUES (?, ?)', 
                       (finding_hash, result_json_str))
        conn.commit()
    conn.close()
    
    return analysis_result

if __name__ == "__main__":
    # Test stub
    dummy_finding = {
        "id": "cwe-79",
        "message": "Potential XSS found.",
        "file": "frontend/app.jsx",
        "line": 42,
        "snippet": "<div dangerouslySetInnerHTML={{__html: userInput}} />"
    }
    dummy_context = "CWE-79: Cross-site Scripting... Fix: Use context-aware encoding."
    
    # This will fail gracefully if Ollama is not actually running.
    res = analyze_finding(dummy_finding, dummy_context)
    print(json.dumps(res, indent=2))
