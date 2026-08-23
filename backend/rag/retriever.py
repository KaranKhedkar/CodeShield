import os
import chromadb
from sentence_transformers import SentenceTransformer

def get_chroma_client():
    db_path = os.path.join(os.path.dirname(__file__), "..", "chroma_db")
    return chromadb.PersistentClient(path=db_path)

def retrieve_context(query: str, n_results: int = 2) -> str:
    """
    Retrieves the most relevant security context (OWASP/CWE) for a given query.
    """
    try:
        client = get_chroma_client()
        collection = client.get_collection(name="security_corpus")
    except Exception as e:
        print(f"ChromaDB error: {e}")
        return "Warning: Security corpus not initialized or not found. Run indexer.py first."

    model = SentenceTransformer('all-MiniLM-L6-v2')
    query_embedding = model.encode(query).tolist()

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )

    if not results or not results['documents'] or not results['documents'][0]:
        return "No relevant security context found."

    context_parts = []
    for i, doc in enumerate(results['documents'][0]):
        title = results['metadatas'][0][i].get('title', 'Unknown Source')
        context_parts.append(f"[{title}]\n{doc}")

    return "\n\n".join(context_parts)

if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "SQL Injection"
    print(f"Retrieving context for: {query}\n")
    print(retrieve_context(query))
