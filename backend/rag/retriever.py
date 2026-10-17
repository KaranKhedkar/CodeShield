import os
from typing import List, Dict, Any
import chromadb
from sentence_transformers import SentenceTransformer

_model = None
_client = None

def get_chroma_client():
    global _client
    if _client is None:
        db_path = os.path.join(os.path.dirname(__file__), "..", "chroma_db")
        _client = chromadb.PersistentClient(path=db_path)
    return _client

def get_embedder():
    global _model
    if _model is None:
        _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model

def retrieve_docs(query: str, n_results: int = 3) -> List[Dict[str, Any]]:
    """
    Returns structured retrieved documents including ID, title, content, and distance.
    """
    try:
        client = get_chroma_client()
        collection = client.get_collection(name="security_corpus")
    except Exception as e:
        print(f"ChromaDB error: {e}")
        return []

    model = get_embedder()
    query_embedding = model.encode(query).tolist()

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )

    if not results or not results['documents'] or not results['documents'][0]:
        return []

    docs = []
    for i in range(len(results['documents'][0])):
        doc_id = results['ids'][0][i]
        content = results['documents'][0][i]
        metadata = results['metadatas'][0][i] if results['metadatas'] else {}
        distance = results['distances'][0][i] if 'distances' in results and results['distances'] else None
        docs.append({
            "id": doc_id,
            "title": metadata.get("title", "Unknown Source"),
            "content": content,
            "distance": distance
        })
    return docs

def retrieve_context(query: str, n_results: int = 2) -> str:
    """
    Retrieves the most relevant security context (OWASP/CWE) for a given query as formatted text.
    """
    docs = retrieve_docs(query, n_results=n_results)
    if not docs:
        return "No relevant security context found."
    return "\n\n".join([f"[{d['title']}]\n{d['content']}" for d in docs])

if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "SQL Injection"
    print(f"Retrieving context for: {query}\n")
    print(retrieve_context(query))

