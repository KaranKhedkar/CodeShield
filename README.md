# CodeShield 🛡️

CodeShield is a local-first, AI-driven security triage tool designed to eliminate alert fatigue from static analysis scanners. 

Static analyzers like Semgrep are incredibly fast and accurate at finding *potential* vulnerabilities, but they often lack the context to determine if a vulnerability is *actually exploitable*. CodeShield solves this by sitting on top of Semgrep and applying a three-step triage pipeline:
1. **Reachability Scoring**: Uses `tree-sitter` to parse your codebase and determine if the vulnerable function is actually imported or called elsewhere in the project.
2. **Knowledge Retrieval (RAG)**: Queries a local `ChromaDB` vector database containing OWASP Top 10 and CWE documentation to ground the analysis in vetted security standards.
3. **Local LLM Investigation**: Feeds the snippet, the call-graph context, and the retrieved security guidelines into a local instance of **Ollama (Qwen3 8B)** to reason about exploitability and generate a cited fix.

All of this happens locally—no code leaves your machine.

---

## 📸 Dashboard

CodeShield features a modern, glassmorphic React dashboard to visualize findings. Instead of sifting through massive JSON files, you can sort findings by their calculated **Risk Score** (a blend of inherent severity and code reachability).

*(Screenshot placeholder: Imagine a stunning dark-mode dashboard with glass panels, a sidebar of historical scans, and an expandable data table highlighting a High Risk SQL Injection.)*

---

## 🚀 Setup & Installation

### Prerequisites
1. **Python 3.10+**
2. **Node.js 18+**
3. **Semgrep** (`pip install semgrep`)
4. **Ollama**: Install [Ollama](https://ollama.com/) and pull the Qwen model: `ollama run qwen3:8b` (or whichever local model you prefer).

### 1. Start the Backend API
You will need two terminals. In the first terminal:
```bash
cd backend
# Windows: .\venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt 

# Build the RAG Corpus (only needed once)
python rag/indexer.py

# Start the FastAPI server (bind to localhost to resolve Vite IPv6 proxy issues)
.\venv\Scripts\activate
uvicorn app.main:app --host localhost --port 8000
```
*(Note: If you don't have Ollama running locally, the backend will gracefully fallback to the Groq API. Just create a `.env` file in the `backend` folder with `GROQ_API_KEY=your_key_here`)*

### 2. Start the Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:5173`. Enter the absolute path to a local repository and click "Run Scan".

---

## 🧠 Architecture Overview
- **Backend Core**: FastAPI, SQLite (SQLAlchemy)
- **Static Analysis**: Semgrep (CLI wrapper)
- **Reachability**: `tree-sitter`, `tree-sitter-python`
- **RAG & Vector DB**: ChromaDB, `sentence-transformers` (`all-MiniLM-L6-v2`)
- **LLM Engine**: Ollama HTTP API
- **Frontend**: React, Vite, Tailwind CSS, Lucide Icons
