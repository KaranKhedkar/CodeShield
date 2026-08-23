import os
import chromadb
from sentence_transformers import SentenceTransformer

# A simplified, static corpus representing OWASP Top 10 and common CWEs
# In a full production system, this would be scraped and chunked from actual documentation.
SECURITY_CORPUS = [
    {
        "id": "owasp-a01-2021",
        "title": "A01:2021 - Broken Access Control",
        "content": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits. Common vulnerabilities include bypassing access control checks, allowing viewing or editing someone else's account, or elevation of privilege. Fix: Implement access control mechanisms once and re-use them throughout the application, including minimizing Cross-Origin Resource Sharing (CORS) usage and enforcing record ownership."
    },
    {
        "id": "owasp-a02-2021",
        "title": "A02:2021 - Cryptographic Failures",
        "content": "Previously known as Sensitive Data Exposure. Focuses on failures related to cryptography, which often lead to sensitive data exposure or system compromise. Common issues include transmitting data in clear text, using weak or old cryptographic algorithms (e.g., MD5, SHA1), or not managing keys properly. Fix: Encrypt all sensitive data at rest and in transit. Use strong, up-to-date standard algorithms, protocols, and keys."
    },
    {
        "id": "owasp-a03-2021",
        "title": "A03:2021 - Injection",
        "content": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. Fix: The primary defense is using a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs)."
    },
    {
        "id": "cwe-79",
        "title": "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
        "content": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. This allows attackers to inject malicious scripts into the web pages viewed by other users. Fix: Use context-aware encoding for all user-controlled data before it is rendered in a browser. Use modern frontend frameworks (like React or Vue) that automatically escape data by default."
    },
    {
        "id": "cwe-20",
        "title": "CWE-20: Improper Input Validation",
        "content": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly. Fix: Assume all input is malicious. Use an 'accept known good' input validation strategy, i.e., use an allowlist of acceptable inputs that strictly conform to specifications."
    }
]

def get_chroma_client():
    # Use a persistent database stored in backend/chroma_db
    db_path = os.path.join(os.path.dirname(__file__), "..", "chroma_db")
    return chromadb.PersistentClient(path=db_path)

def build_index():
    print("Initializing ChromaDB and loading embedding model...")
    client = get_chroma_client()
    
    # We will use sentence-transformers for embedding
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    collection_name = "security_corpus"
    try:
        collection = client.get_collection(name=collection_name)
        print(f"Collection '{collection_name}' already exists. Skipping ingestion.")
        return
    except Exception as e:
        print(f"Creating collection '{collection_name}'...")
        collection = client.create_collection(name=collection_name)
    
    print("Embedding and indexing security corpus...")
    
    texts = []
    ids = []
    metadatas = []
    
    for item in SECURITY_CORPUS:
        # We embed the combination of title and content
        texts.append(f"{item['title']}\n{item['content']}")
        ids.append(item['id'])
        metadatas.append({"title": item['title'], "source": "OWASP/CWE"})
        
    embeddings = model.encode(texts).tolist()
    
    collection.add(
        ids=ids,
        embeddings=embeddings,
        documents=[item['content'] for item in SECURITY_CORPUS],
        metadatas=metadatas
    )
    print("Ingestion complete. RAG corpus is ready.")

if __name__ == "__main__":
    build_index()
