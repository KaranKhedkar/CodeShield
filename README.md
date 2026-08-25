# CodeShield 🛡️

**CodeShield** is a next-generation Static Application Security Testing (SAST) tool powered by Agentic AI. It automatically scans codebases to detect vulnerabilities, filters out false positives using structural reachability analysis, and leverages a LangGraph-powered LLM agent to provide actionable explanations and 1-click automated code fixes.

## Key Features

* **Advanced SAST Scanning:** Uses Semgrep to quickly identify security flaws in local codebases and remote GitHub repositories.
* **Reachability Analysis:** Leverages Tree-sitter to analyze Python syntax trees, scoring risk and filtering out unreachable or "dead" code to drastically reduce false positives.
* **Agentic AI Resolution:** Employs a LangGraph workflow and Groq (Llama-3) to investigate high-risk findings, verify vulnerabilities, and explain the root cause.
* **Automated Remediation:** Synthesizes precise code patches and allows users to fix vulnerabilities directly from the UI with a 1-click "Apply Fix" button.
* **RAG Knowledge Base:** Incorporates ChromaDB and Sentence-Transformers to ground AI responses in verified security rule documentation.

## Screenshots / Demo

*(Below are previews of the CodeShield UI)*

| Landing Page | Dashboard Scan |
| :---: | :---: |
| ![Landing Page](docs/landing-page.png) | ![Dashboard](docs/dashboard.png) |

| Scanning Progress | AI Explanation & Fix |
| :---: | :---: |
| ![Scan](docs/scan.png) | ![Explanation](docs/explanation.png) |

## Tech Stack

* **Frontend:** React, Vite, TailwindCSS, Lucide Icons
* **Backend:** Python 3.13, FastAPI, Uvicorn
* **Database & Cache:** SQLite (History tracking), Redis (LLM caching & performance)
* **AI / ML:** LangGraph, LangChain, Groq (Llama-3), ChromaDB, Sentence-Transformers
* **Deployment / DevOps:** Docker, Docker Compose, Nginx, Render (Backend), Vercel (Frontend)

## How It Works

1. **Input:** The user provides a local directory path or a public GitHub URL in the React frontend.
2. **Analysis:** The FastAPI backend enqueues a background task that clones the repository and runs `semgrep` for raw static analysis.
3. **Filtering:** `tree-sitter-python` parses the AST (Abstract Syntax Tree) to determine if the vulnerable functions are actually reachable, assigning a calculated risk score.
4. **Agentic Verification:** High-risk findings are dispatched to a LangGraph Agent. The agent queries ChromaDB (RAG) for the context of the specific Semgrep rule and prompts the Groq LLM to verify the finding and generate a patch.
5. **Remediation:** The frontend retrieves the completed scan and displays the AI's explanation. The user can click "Apply Fix" to automatically replace the vulnerable code snippet with the AI-generated patch on disk.

## Project Structure

```text
├── backend/
│   ├── app/           # FastAPI application, routes, and background tasks
│   ├── core/          # Semgrep execution wrapper and Tree-sitter reachability logic
│   ├── db/            # SQLite models and session management
│   ├── llm/           # LangGraph agent orchestration and Groq LLM integration
│   ├── rag/           # ChromaDB retriever and Sentence-Transformers embedding setup
│   ├── Dockerfile     # Production-ready Python backend container image
│   └── requirements.txt
├── frontend/
│   ├── src/           # React components, pages, and Tailwind styling
│   ├── nginx.conf     # Production Nginx web server config and API proxy routing
│   ├── Dockerfile     # Multi-stage Node/Nginx frontend build
│   └── package.json
├── docs/              # UI Screenshots
└── docker-compose.yml # Local development container orchestration
```

## Installation & Setup

You can easily run CodeShield locally using Docker.

**Prerequisites:** Ensure you have [Docker](https://www.docker.com/products/docker-desktop/) and Docker Compose installed on your machine.

1. **Clone the repository**
   ```bash
   git clone https://github.com/KaranKhedkar/CodeShield.git
   cd CodeShield
   ```

2. **Setup Environment Variables**
   Create a `.env` file in the `backend/` directory:
   ```bash
   touch backend/.env
   ```
   Add your Groq API key to the file (see section below).

3. **Build and Run the Containers**
   ```bash
   docker-compose up --build
   ```
   *Note: On the first run, the backend will automatically download the required `all-MiniLM-L6-v2` Sentence-Transformer model.*

4. **Access the Application**
   Open your browser and navigate to `http://localhost`.

## Environment Variables

The backend requires the following environment variables. Do not commit your real `.env` file to version control.

```env
# backend/.env
GROQ_API_KEY=your_groq_api_key_here

# The following is handled automatically by Docker Compose, but can be overridden:
REDIS_URL=redis://redis:6379/0
```

## Usage

1. Open the CodeShield dashboard at `http://localhost`.
2. Enter a **GitHub Repository URL** (e.g., `https://github.com/KaranKhedkar/Amazon_clone`) or a valid absolute local path.
3. Click **Scan**. CodeShield will process the codebase in the background.
4. Once completed, review the list of detected vulnerabilities. Click on any finding to expand the AI's explanation, confidence score, and suggested code patch.
5. Click **Apply Fix** to automatically write the AI's patch to the source code file (only works for local directory scans).

## AI/ML Details

CodeShield moves beyond traditional regex-based SAST tools by incorporating a specialized AI workflow:
* **Models:** Uses `llama3-70b-8192` via Groq for high-speed, intelligent reasoning and code synthesis.
* **Embeddings:** Uses `all-MiniLM-L6-v2` (via `sentence-transformers`) to generate semantic embeddings of security rules.
* **Vector Database:** ChromaDB stores and retrieves security context, acting as the foundation for the Retrieval-Augmented Generation (RAG) pipeline.
* **Agentic Orchestration:** LangGraph manages the decision-making loop. The AI is explicitly instructed to act as a Senior Security Engineer, combining the raw Semgrep output with retrieved RAG context to filter false positives and output deterministic JSON patches.

## Future Improvements

* **Multi-Language Reachability:** Expand the Tree-sitter reachability analysis (currently optimized for Python) to fully support JavaScript, TypeScript, and Go.
* **Authentication & RBAC:** Implement user accounts and Role-Based Access Control to manage private scan histories.
* **CI/CD Integration:** Develop a GitHub Action to automatically trigger CodeShield scans on pull requests.
* **IDE Plugin:** Create a VSCode extension to run the agentic verification pipeline directly in the developer's editor.

## Author

**Karan Khedkar**
- [GitHub](https://github.com/KaranKhedkar)
