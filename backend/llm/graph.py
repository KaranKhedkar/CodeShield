import os
import json
from typing import TypedDict, Dict, Any
from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv

load_dotenv()

# Dynamic LLM Provider Selection
# If a GROQ_API_KEY is provided, use the fast cloud LPU.
# Otherwise, strictly fallback to the local, privacy-preserving Ollama model.
api_key = os.environ.get("GROQ_API_KEY")
if api_key:
    from langchain_groq import ChatGroq
    llm = ChatGroq(
        model="openai/gpt-oss-120b",  # Fast Groq Model
        temperature=0.2,
        api_key=api_key,
    ).bind(response_format={"type": "json_object"})
else:
    from langchain_community.chat_models import ChatOllama
    llm = ChatOllama(
        model="qwen3:8b",  # Local Ollama Fallback
        temperature=0.2,
        format="json"
    )

class GraphState(TypedDict):
    finding: Dict[str, Any]
    rag_context: str
    analysis: str
    confidence: str
    fix_recommendation: str
    patch_target: str
    patch_replacement: str

def analyst_node(state: GraphState):
    """Analyzes the finding to determine exploitability."""
    finding = state["finding"]
    context = state["rag_context"]
    
    prompt = f"""You are an expert Application Security Analyst. Review the static analysis finding and security documentation.
Determine if this finding is genuinely exploitable in the provided code snippet. 

SECURITY DOCUMENTATION:
{context}

STATIC ANALYSIS FINDING:
Rule ID: {finding.get('id')}
File: {finding.get('file')}
Line: {finding.get('line')}
Code Snippet:
```
{finding.get('snippet')}
```

Provide your reasoning and a confidence score.
Output STRICTLY in JSON format:
{{
    "analysis": "A clear explanation of whether this is exploitable and why.",
    "confidence": "High, Medium, or Low"
}}
"""
    try:
        response = llm.invoke(prompt)
        result = json.loads(response.content)
        return {
            "analysis": result.get("analysis", "Failed to parse analysis."), 
            "confidence": result.get("confidence", "Low")
        }
    except Exception as e:
        print(f"Analyst node error: {e}")
        return {"analysis": f"Analysis failed: {str(e)}", "confidence": "Low"}

def fixer_node(state: GraphState):
    """Drafts a fix based on the analyst's findings."""
    finding = state["finding"]
    analysis = state["analysis"]
    
    prompt = f"""You are an expert Security Engineer fixing vulnerabilities.
Review the original code and the Analyst's report to provide a secure code fix.

ORIGINAL SNIPPET:
```
{finding.get('snippet')}
```

ANALYST REPORT:
{analysis}

Provide your recommended fix.
You MUST also provide a strict machine-readable code patch.
Set `patch_target` to the exact lines in the ORIGINAL SNIPPET that need to be replaced. This must match character-for-character.
Set `patch_replacement` to your secure code that should replace the `patch_target`.

Output STRICTLY in JSON format:
{{
    "fix": "The recommended fix or code rewrite.",
    "patch_target": "original lines to replace",
    "patch_replacement": "secure lines to insert"
}}
"""
    try:
        response = llm.invoke(prompt)
        result = json.loads(response.content)
        return {
            "fix_recommendation": result.get("fix", "No fix generated."),
            "patch_target": result.get("patch_target"),
            "patch_replacement": result.get("patch_replacement")
        }
    except Exception as e:
        print(f"Fixer node error: {e}")
        return {
            "fix_recommendation": f"Failed to generate fix: {str(e)}",
            "patch_target": None,
            "patch_replacement": None
        }

# Build graph
workflow = StateGraph(GraphState)
workflow.add_node("analyst", analyst_node)
workflow.add_node("fixer", fixer_node)

workflow.add_edge(START, "analyst")
workflow.add_edge("analyst", "fixer")
workflow.add_edge("fixer", END)

# Compile into a runnable application
app = workflow.compile()
