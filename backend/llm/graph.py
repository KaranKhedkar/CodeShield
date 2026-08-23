import os
import json
from typing import TypedDict, Dict, Any
from langgraph.graph import StateGraph, START, END
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

# We will use ChatGroq for reliable JSON output in the multi-agent orchestration
llm = ChatGroq(
    model="openai/gpt-oss-20b",
    temperature=0.2,
    api_key=os.environ.get("GROQ_API_KEY"),
).bind(response_format={"type": "json_object"})

class GraphState(TypedDict):
    finding: Dict[str, Any]
    rag_context: str
    analysis: str
    confidence: str
    fix_recommendation: str

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
Output STRICTLY in JSON format:
{{
    "fix": "The recommended fix or code rewrite."
}}
"""
    try:
        response = llm.invoke(prompt)
        result = json.loads(response.content)
        return {"fix_recommendation": result.get("fix", "No fix generated.")}
    except Exception as e:
        print(f"Fixer node error: {e}")
        return {"fix_recommendation": f"Failed to generate fix: {str(e)}"}

# Build graph
workflow = StateGraph(GraphState)
workflow.add_node("analyst", analyst_node)
workflow.add_node("fixer", fixer_node)

workflow.add_edge(START, "analyst")
workflow.add_edge("analyst", "fixer")
workflow.add_edge("fixer", END)

# Compile into a runnable application
app = workflow.compile()
