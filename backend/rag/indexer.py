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
        "id": "cwe-89",
        "title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "content": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but fails to neutralize or incorrectly neutralizes special elements that could modify the intended SQL command. This allows attackers to manipulate query logic, bypass authentication, and extract or delete data. Fix: Always use parameterized queries (prepared statements) with bound variables (e.g., cursor.execute('SELECT * FROM users WHERE name = %s', (username,)) in Python DB-API or ORM query abstractions like SQLAlchemy/Django ORM). Never concatenate or interpolate user input strings directly into SQL queries."
    },
    {
        "id": "cwe-78",
        "title": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "content": "The application constructs an operating system command using externally-influenced input and passes it to a command shell interpreter (e.g., subprocess.check_output, subprocess.Popen, os.system). Attackers can append command separators like ;, &&, or | to execute arbitrary system commands with the privileges of the web application. Fix: Avoid executing operating system commands whenever native language libraries are available. Never execute commands through a system shell (set shell=False in subprocess) and pass arguments as an explicit tokenized list (e.g., subprocess.run(['ping', '-c', '1', host])). If a shell cannot be avoided, strictly validate against an allowlist and escape inputs using shlex.quote()."
    },
    {
        "id": "cwe-94",
        "title": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
        "content": "The application receives untrusted input and passes it to dynamic evaluation functions such as eval(), exec(), or compile(). This enables attackers to inject and execute arbitrary language-level code within the application process. Fix: Eliminate all dynamic code evaluation. Replace eval() with safe parsers such as ast.literal_eval() for structured data literals, or implement dedicated math expression parsers. Never pass user-controllable strings to dynamic interpreters."
    },
    {
        "id": "cwe-79",
        "title": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "content": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. This allows attackers to inject malicious scripts into the web pages viewed by other users. Fix: Use context-aware encoding for all user-controlled data before it is rendered in a browser. Use modern frontend frameworks (like React or Vue) that automatically escape data by default. Avoid dangerouslySetInnerHTML or unescaped template tags."
    },
    {
        "id": "cwe-798",
        "title": "CWE-798: Use of Hard-coded Credentials",
        "content": "The software contains hard-coded credentials, such as cleartext passwords, cryptographic keys, database secrets, or API tokens directly within its source code. Anyone with access to the codebase or decompiled binaries can extract these credentials. Fix: Remove all hard-coded credentials from source files. Load secrets dynamically from environment variables using os.environ or a dedicated secret management vault (e.g., AWS Secrets Manager, HashiCorp Vault)."
    },
    {
        "id": "cwe-22",
        "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "content": "The application uses external input to construct pathnames for filesystem operations without properly resolving or validating that the path remains within the intended root directory. Attackers can supply relative sequences like ../ to access sensitive system files. Fix: Sanitize filenames using os.path.basename(). Resolve canonical paths using os.path.realpath() and verify that the target path begins with the trusted directory prefix using startswith()."
    },
    {
        "id": "cwe-20",
        "title": "CWE-20: Improper Input Validation",
        "content": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly. Fix: Assume all input is malicious. Use an 'accept known good' input validation strategy, i.e., use an allowlist of acceptable inputs that strictly conform to specifications (types, lengths, and expected character sets)."
    },
    {
        "id": "cwe-502",
        "title": "CWE-502: Deserialization of Untrusted Data",
        "content": "The application deserializes untrusted data without sufficient verification, using unsafe serializers such as Python's pickle or PyYAML yaml.load(). Pickled byte streams can instantiate arbitrary classes and execute code upon deserialization. Fix: Avoid unsafe serialization formats. Replace pickle with secure, standard serialization formats such as JSON (json.loads) or use yaml.safe_load() with PyYAML."
    },
    {
        "id": "cwe-918",
        "title": "CWE-918: Server-Side Request Forgery ('SSRF')",
        "content": "The web server receives a user-supplied URL and makes an outbound HTTP request to that URL without validating the destination host. Attackers can leverage this to probe internal networks, cloud metadata services (e.g., 169.254.169.254), or local services (localhost / 127.0.0.1). Fix: Validate user-supplied URLs against an allowlist of permitted domain names. Block requests destined for internal, loopback, or private RFC 1918 IP addresses."
    }
]

def get_chroma_client():
    # Use a persistent database stored in backend/chroma_db
    db_path = os.path.join(os.path.dirname(__file__), "..", "chroma_db")
    return chromadb.PersistentClient(path=db_path)

def build_index(force_rebuild: bool = False):
    print("Initializing ChromaDB and loading embedding model...")
    client = get_chroma_client()
    
    # We will use sentence-transformers for embedding
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    collection_name = "security_corpus"
    if force_rebuild:
        try:
            client.delete_collection(name=collection_name)
            print(f"Deleted existing collection '{collection_name}' for clean rebuild.")
        except Exception:
            pass

    try:
        collection = client.get_collection(name=collection_name)
        if not force_rebuild and collection.count() == len(SECURITY_CORPUS):
            print(f"Collection '{collection_name}' already exists with {collection.count()} docs. Skipping ingestion.")
            return
        elif not force_rebuild:
            print(f"Collection count ({collection.count()}) != corpus size ({len(SECURITY_CORPUS)}). Updating collection...")
    except Exception:
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
    
    # Upsert or delete & add to avoid duplicate key errors
    try:
        client.delete_collection(name=collection_name)
    except Exception:
        pass
    collection = client.create_collection(name=collection_name)

    collection.add(
        ids=ids,
        embeddings=embeddings,
        documents=[item['content'] for item in SECURITY_CORPUS],
        metadatas=metadatas
    )
    print(f"Ingestion complete. RAG corpus is ready with {len(ids)} security documents.")

if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    build_index(force_rebuild=force)
