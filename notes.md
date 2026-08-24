# CodeShield Project Notes

## Milestone 1: Detection + Reachability

### 1. Explanation
In this first milestone, the core detection capability was established by integrating Semgrep as the static analysis engine, paired with a custom tree-sitter reachability layer. Instead of reinventing vulnerability detection from scratch, Semgrep is invoked as a subprocess to rapidly scan target directories using its extensive rule sets. However, Semgrep findings alone can be noisy and lack context about how the vulnerable code is actually used. To address this, a reachability engine was built using tree-sitter (initially targeting Python). By parsing the AST (Abstract Syntax Tree) of the vulnerable file, we identify the specific function or class containing the vulnerability. The engine then scans other files in the codebase, building a primitive call graph by counting how often that function is invoked. Finally, the raw severity from Semgrep (e.g., Error, Warning) is combined mathematically with this reachability score to produce a single, actionable Risk Score (0-100). This ensures developers focus first on high-severity vulnerabilities that are actively called and thus genuinely exploitable, effectively reducing alert fatigue.

### 2. Architecture
- **Semgrep Wrapper (`backend/core/semgrep_wrapper.py`)**: Executes `semgrep scan --json` via Python's subprocess, captures the output, and normalizes the results into a standard JSON schema containing severity, file path, line number, and snippet.
- **Reachability Engine (`backend/core/reachability.py`)**: 
  - Uses `tree-sitter-python` to parse the vulnerable file and locate the enclosing AST node (function/class definition).
  - Traverses the AST of other project files to count identifiers/calls matching the vulnerable node's name.
- **Risk Scorer**: Computes a weighted Risk Score (`(Severity Score * 0.6) + (Reachability Score * 0.4) * 100`).

### 3. Interview Q&A
**Q: Why use Semgrep instead of writing your own static analysis rules or using LLMs directly for detection?**
A: I chose Semgrep because it is an industry standard, lightning-fast, and comes with thousands of community-vetted rules. Using an LLM to scan an entire codebase for initial detection is too slow, expensive, and context-window limited. Semgrep acts as a high-recall filter, passing only the suspicious areas to the more advanced analysis pipeline.

**Q: Why use tree-sitter for reachability instead of regex or grep?**
A: I chose tree-sitter because it parses the code into a true Abstract Syntax Tree. Regex is brittle—it can easily be fooled by comments, strings, or similarly named variables in different scopes. Tree-sitter understands the language grammar, allowing me to precisely locate function definitions and their invocations, leading to a much more accurate reachability score.

**Q: How is the final risk score calculated, and why weight it that way?**
A: The risk score combines the inherent severity of the vulnerability (e.g., an RCE vs a minor lint issue) weighted at 60%, and the reachability (how often it's called) weighted at 40%. I chose this weighting because a critical vulnerability that is unreachable is still a potential liability if code changes, but a medium severity issue that is exposed on a public endpoint needs immediate attention.

**Q: What are the limitations of this current reachability approach?**
A: The current implementation uses a heuristic based on function name matching across the AST of other files. It doesn't trace full data flow (taint analysis) or handle dynamic dispatch/polymorphism perfectly. However, it's a lightweight proxy that effectively filters out truly dead code without the massive overhead of compiling a full, strict call graph.

**Q: Why run Semgrep as a subprocess instead of using its Python API?**
A: Semgrep's Python API is not formally stable or documented for external consumption in the same way the CLI is. Invoking the CLI via subprocess and parsing the JSON output is the officially supported, most robust way to integrate it into custom tooling without tying the project to internal Semgrep implementation details.

## Milestone 2: RAG Corpus + Retrieval

### 1. Explanation
The second milestone establishes the knowledge backbone of CodeShield by implementing a Retrieval-Augmented Generation (RAG) system over security best practices. When static analysis tools output a vulnerability, they often lack sufficient remediation context, leaving developers to Google the issue. To solve this locally, I built an ingestion pipeline that takes official OWASP Top 10 and CWE documentation, chunks the text, and computes dense vector embeddings using the `all-MiniLM-L6-v2` model from `sentence-transformers`. These embeddings are stored locally in a persistent ChromaDB vector database. When a vulnerability is found in the pipeline, the retriever takes the Semgrep finding context (like the rule ID or a description snippet) and queries ChromaDB. The database returns the most semantically relevant security guidelines and mitigation strategies, which are then injected into the context window of the local LLM in the next milestone. This grounds the LLM's remediation advice in authoritative, vetted security standards rather than relying solely on its internal training weights.

### 2. Architecture
- **Indexer (`backend/rag/indexer.py`)**: Defines the target security corpus (OWASP/CWE), initializes `SentenceTransformer` to generate vector embeddings, and stores them in a local ChromaDB collection (`security_corpus`).
- **Retriever (`backend/rag/retriever.py`)**: Takes a query string (e.g., "SQL Injection"), generates its embedding, performs a similarity search against the ChromaDB collection, and returns the top `k` most relevant context passages.
- **Local Database (`backend/chroma_db`)**: The persistent storage folder where ChromaDB writes its vector indices, ensuring we don't have to re-embed the corpus on every scan.

### 3. Interview Q&A
**Q: Why use ChromaDB over a hosted vector database like Pinecone or Weaviate?**
A: The core design philosophy of CodeShield is that it is a "local-first" triage tool. Sending proprietary codebase vulnerabilities to a cloud vector database or relying on cloud embeddings introduces privacy risks and latency. ChromaDB runs entirely locally and persists to the disk, which perfectly fits the requirement of an offline, private security pipeline.

**Q: Why use `all-MiniLM-L6-v2` for embeddings instead of OpenAI's `text-embedding-ada-002`?**
A: Aside from the local-first requirement preventing API usage, `all-MiniLM-L6-v2` is incredibly fast, lightweight, and achieves excellent semantic similarity performance for general text retrieval. It easily runs on a standard CPU without needing a dedicated GPU, which keeps the tool's infrastructure footprint small.

**Q: In a production scenario, how would you handle updating the RAG corpus?**
A: The ingestion script would be updated to pull dynamically from OWASP and MITRE CWE RSS feeds, GitHub repositories, or standard PDF exports. We would run a cron job to detect document updates, chunk the new text, compute the embeddings, and perform an upsert into ChromaDB based on document IDs.

**Q: Why do RAG at all? Doesn't a model like Qwen3 already know about SQL Injection?**
A: Yes, large language models have internalized general security knowledge. However, RAG grounds the model's response in specific, authoritative, and up-to-date documentation. It prevents the model from hallucinating a fix, provides exact citations (which builds developer trust), and allows us to easily inject company-specific security policies into the context without fine-tuning the model.

## Milestone 3: Local LLM Investigation Pipeline

### 1. Explanation
The third milestone bridges the detection and knowledge retrieval systems using a local Large Language Model (LLM) to perform the actual security triage. I integrated Ollama, running the locally-hosted Qwen3 8B model (4-bit quantized), to act as the reasoning engine. The pipeline takes the raw Semgrep finding (file, line, code snippet) and concatenates it with the context retrieved from ChromaDB to construct a detailed prompt. The LLM is instructed to determine if the vulnerability is genuinely exploitable in its specific context, assign a confidence label, and generate a cited fix. Crucially, I implemented a SQLite-based caching layer. Because LLM inference is computationally expensive—especially on local hardware—each unique combination of a vulnerability and its context is hashed using SHA-256. Before querying Ollama, the pipeline checks the cache; if a finding has already been analyzed in a previous scan and hasn't changed, the cached JSON response is instantly returned. This drastically speeds up subsequent repository scans.

### 2. Architecture
- **LLM Analyzer (`backend/llm/analyzer.py`)**: The central integration point for Ollama. Constructs the structured prompt combining the static analysis finding and RAG context.
- **Ollama API Integration**: Uses standard HTTP POST requests to query the local Ollama instance (`http://localhost:11434/api/generate`) requesting JSON-formatted output.
- **SQLite Cache Layer**: A local SQLite database (`llm_cache.db`) storing the SHA-256 hash of findings alongside the LLM's JSON response to prevent redundant, expensive LLM calls on re-scans.

### 3. Interview Q&A
**Q: Why use Ollama running locally instead of an OpenAI API?**
A: The strict constraint for CodeShield is to remain a local-first tool. Sending proprietary, potentially sensitive code snippets and vulnerability data to third-party cloud LLM APIs is often a non-starter for enterprise security teams. Ollama allows us to run highly capable, quantized models like Qwen3 entirely on-device, preserving privacy and eliminating ongoing API costs.

**Q: Why cache by finding hash rather than just by file or Semgrep rule ID?**
A: Caching strictly by file is too broad—if a developer fixes one vulnerability but leaves another in the same file, the whole file shouldn't be re-analyzed. Caching by rule ID is too narrow—the same rule violation in two different contexts requires two different explanations. By hashing the exact snippet, rule ID, and surrounding context, we guarantee that the LLM only re-analyzes a finding if the code or the context itself has actually changed.

**Q: How does the pipeline ensure the LLM returns usable, structured data instead of a conversational block of text?**
A: The prompt is heavily engineered to mandate a specific JSON structure (`explanation`, `confidence`, `fix`). Furthermore, when querying the Ollama API, I pass the `format: "json"` parameter, which leverages the model's native JSON mode (if supported) or strongly biases it to output parseable JSON, allowing the backend to reliably ingest the data for the frontend dashboard.

## Milestone 4: Backend API

### 1. Explanation
In the fourth milestone, I wrapped the entire core pipeline—detection, reachability, RAG, and LLM investigation—into a REST API using FastAPI. This API serves as the bridge between the heavy backend processing and the frontend dashboard. I implemented endpoints to trigger an asynchronous scan on a local directory (`POST /scan`), fetch the detailed results of a specific scan (`GET /scan/{id}`), and list the historical log of all previous scans (`GET /history`). To manage state and persist the results, I used SQLAlchemy as an ORM connected to a SQLite database. When a scan is triggered, it returns an ID immediately and runs the heavy LLM pipeline in a FastAPI `BackgroundTask`. This ensures the API remains highly responsive and doesn't time out while Ollama is analyzing dozens of findings.

### 2. Architecture
- **FastAPI App (`backend/app/main.py`)**: The main entry point exposing the REST endpoints and utilizing `BackgroundTasks` for asynchronous scanning.
- **SQLAlchemy Models (`backend/app/db/models.py`)**: Defines the relational schemas for `ScanHistory` and `Finding` tables.
- **Database Session (`backend/app/db/session.py`)**: Configures the connection to the SQLite database (`codeshield.db`).

### 3. Interview Q&A
**Q: Why use FastAPI instead of Flask or Django?**
A: FastAPI is perfectly suited for this project because it is exceptionally fast, built on modern Python type hints (which auto-generates Swagger documentation), and natively supports asynchronous operations. Since LLM generation and Semgrep subprocess calls are heavily I/O bound, FastAPI's async capabilities and built-in `BackgroundTasks` make it easy to prevent the server from blocking during long scans without needing a heavy external task queue like Celery.

**Q: Why use SQLite for storage instead of PostgreSQL or MongoDB?**
A: CodeShield is designed to be a lightweight, local-first developer tool. Requiring a developer to spin up a Postgres Docker container just to run a local static analysis triage tool adds unnecessary friction. SQLite is built into Python, requires zero configuration, stores data in a single file, and is more than capable of handling the concurrent read/writes expected from a single-user dashboard.

**Q: How does the frontend know when a scan is finished since it runs in the background?**
A: The `POST /scan` endpoint immediately returns a `scan_id`. The frontend will then poll the `GET /scan/{scan_id}` endpoint. The database schema includes a `status` field (e.g., `running`, `completed`, `failed`). The frontend continues polling until the status changes to `completed`, at which point it renders the findings. In a production v2, this could be upgraded to WebSockets or Server-Sent Events (SSE) for real-time streaming, but polling is a robust and simple solution for v1.

## Milestone 5: Frontend Dashboard

### 1. Explanation
The fifth milestone brings CodeShield to life by providing a visual interface for developers to triage vulnerabilities. Instead of sifting through massive JSON outputs in the terminal, developers use a modern React application. Built with Vite and styled using Tailwind CSS, the dashboard features a dark-themed, glassmorphic UI that feels premium and developer-centric. It provides a clean layout with a sidebar for historical scans and a main view for active scan results. The core feature is a sortable findings table that prioritizes issues based on the previously calculated Risk Score. Developers can instantly see high-risk vulnerabilities at the top. Clicking on a row expands an accordion to reveal the LLM's plain-English explanation of exploitability, its confidence level, and a cited fix recommendation grounded in OWASP/CWE documentation. This visual hierarchy directly addresses the problem of alert fatigue.

### 2. Architecture
- **React + Vite (`frontend/src/App.jsx`)**: The main Single Page Application (SPA) utilizing functional components and React hooks (`useState`, `useEffect`) to manage state and API polling.
- **Tailwind CSS (`frontend/src/index.css`)**: A utility-first CSS framework used for styling, heavily employing custom classes like `.glass-panel` to achieve the modern aesthetic.
- **Lucide Icons**: Integrated for scalable, consistent vector iconography across the dashboard (e.g., shields, loader spinners, expand chevrons).

### 3. Interview Q&A
**Q: Why build a custom React dashboard instead of just outputting a static HTML report or a CLI table?**
A: While a CLI or static HTML is easier to build, a core goal of CodeShield is to improve the developer experience and reduce triage fatigue. An interactive React dashboard allows for dynamic sorting by risk score, expandable rows for deep-dive LLM explanations, and easy access to historical scans. It transforms static analysis from a raw data dump into an interactive triage workflow.

**Q: How did you manage state for the asynchronous scanning process in React?**
A: I used a combination of `useState` to track the current `scanId` and `useEffect` with `setInterval` to establish a polling mechanism. When a scan is triggered, the app receives the `scanId` and begins polling the backend every 3 seconds. Once the backend status transitions from `running` to `completed`, the interval is cleared, and the final findings are rendered.

**Q: Why Tailwind CSS over traditional CSS modules or styled-components?**
A: Tailwind CSS allows for rapid prototyping and enforces a consistent design system directly in the markup. By avoiding context-switching between JS and CSS files, I was able to build a polished, responsive, and glassmorphic UI much faster. It also automatically purges unused styles, resulting in a tiny production CSS bundle.

## Future Work (v2)

### LangGraph Multi-Agent Orchestration
For the v2 direction of CodeShield, the single, linear LLM investigation pipeline will be split into specialized, coordinating agents orchestrated by **LangGraph**. Instead of a single LLM call attempting to do everything (explain, assess confidence, and write a fix), the system will use a graph of specialized agents:
- **Security Reasoning Agent**: Focuses strictly on whether the code path is exploitable.
- **Dependency Agent**: Checks if the vulnerability stems from a known compromised supply-chain dependency.
- **Evidence Agent**: Navigates the codebase to pull additional surrounding context (e.g., looking up definitions of custom validation functions used in the snippet).
- **Fix Agent**: Drafts the remediation code and verifies it doesn't break syntax.

### Why this is deferred, not built now
A single reasoning pipeline is sufficient to prove the core concept: that context-aware, RAG-backed LLM investigation beats raw static-analysis output. Implementing multi-agent orchestration adds significant complexity, debugging overhead, and latency. Validating the core user experience (alert fatigue reduction) must come first. Multi-agent is a scaling and specialization improvement to be introduced once the core loop is validated, not a requirement to demonstrate the initial concept.

### What it would unlock
Migrating to LangGraph unlocks parallel investigation of independent findings, significantly speeding up large repository scans. It allows agents to use specialized tools (e.g., the Dependency Agent querying the National Vulnerability Database API directly, or the Evidence Agent using tree-sitter dynamically to fetch more code). It also provides a much clearer separation of concerns, making the system easier to test and extend as the definition of "triage" grows to include automated pull request generation or fix verification.

### Interview Q&A
**Q: Why didn't you build a multi-agent system for v1?**
A: For an MVP, the primary risk to retire was proving that an LLM grounded in RAG could successfully filter false positives from Semgrep. A single prompt pipeline achieved this effectively. Introducing LangGraph early on would have added state-management complexity and debugging overhead that didn't directly contribute to validating the core value proposition.

**Q: How would you architect the multi-agent version?**
A: I would use LangGraph to define a state graph where the `State` object holds the Semgrep finding, the collected evidence, and the draft analysis. The graph would start with a "Router" node that decides which specialist agents need to be invoked (e.g., routing to the Dependency Agent if it's an import issue). The agents would execute and write their findings back to the shared `State`, culminating in a final "Synthesizer" node that formats the output for the dashboard.

**Q: How do agents share context in your proposed LangGraph architecture?**
A: LangGraph utilizes a centralized `State` (typically a typed dictionary or Pydantic model). As each agent node is invoked, it receives the current state, performs its specific reasoning or tool calls, and returns updates (like appending a piece of evidence or a draft fix) that are merged into the global state, ensuring the next agent in the graph has the full, updated context.


## Landing Page (Frontend UI)

**Design Reasoning:**
The landing page was designed to embody the core value proposition of CodeShield: turning noisy, raw security findings into a clear, explained signal. Instead of relying on generic SaaS tropes or abstract illustrations, the page features a split-hero layout with a live, animated preview of the actual findings table. This approach immediately demonstrates the product's utility�risk scores counting up and statuses resolving from 'investigating' to 'explained'�before the user even clicks 'Start Scan'. The color palette (graphite backgrounds, amber signal accents, teal verified states) and typography (Space Grotesk for display, JetBrains Mono for data) reinforce the tool's identity as a serious, technical instrument rather than a flashy marketing toy.

**Potential Interview Questions & Answers:**
**Q: Why did you build a landing page for a developer tool instead of just dropping users into the dashboard?**
**A:** A landing page frames the problem before showing the solution. It demonstrates product thinking by establishing context and setting expectations. For a tool that solves 'alert fatigue', showing the noise-to-signal transition upfront proves the tool's value immediately, rather than forcing the user to run a scan before understanding what the tool actually does.

**Q: How did you implement the live preview animation without hitting the backend?**
**A:** The hero preview uses static mock data animated entirely on the client side using React \useEffect\ hooks. We use a simple \setInterval\ with an easing function to count up the risk scores, and a \setTimeout\ to transition the status badge state. This provides a highly engaging micro-interaction with zero latency or backend dependency, while gracefully degrading if the user prefers reduced motion.

**Q: How did you structure the CSS and theming to ensure consistency between the landing page and the app?**
**A:** We abstracted the core design tokens into \	ailwind.config.js\ using semantic names (e.g., \core-bg\, \ccent-signal\) rather than raw color values. This ensures that the landing page and the dashboard share the exact same visual language. We also mapped specific fonts (like JetBrains Mono) to data-heavy elements across both routes to create visual continuity.

### v1.1 Speed Optimizations
To make scanning larger repositories significantly faster, we implemented the following performance optimizations:
1. **Parallel LLM Investigation**: Migrated from sequential processing to concurrent processing using Python's `ThreadPoolExecutor`. Scans with multiple findings now query the local LLM and Vector DB concurrently, dramatically reducing total latency.
2. **Threshold Filtering**: AI triage is now intentionally bypassed for "Low Risk" (score < 40) informational findings to preserve compute resources and prioritize high-risk, reachable vulnerabilities.
3. **Semgrep Tuning**: Hardcoded multi-threading (`--jobs 4`) and additional ignore paths (`build`, `dist`) to the underlying static analysis engine.
4. **Hybrid Persistent Caching (Redis + SQLite)**: Out-of-the-box persistent caching. The backend attempts to connect to Redis (if `REDIS_URL` is set) for ultra-fast, distributed caching. If Redis is unavailable, it seamlessly falls back to a local SQLite database (`llm_cache.db`). A SHA-256 fingerprint of the vulnerability snippet and rule ID prevents duplicate LLM requests for unchanged code across rescans.

### v2.0 LangGraph Multi-Agent Architecture
To increase the quality of the LLM analysis, we migrated from a monolithic single-prompt architecture to a multi-agent orchestration using langgraph. The pipeline is now split into two specialized agents:
1. **Analyst Node**: Focuses purely on determining exploitability and assigning a confidence score.
2. **Fixer Node**: Drafts a precise code remediation based on the finding and the Analyst's report.

This architecture sets the foundation for adding more tools (e.g., repository navigation, dependency checking) in the future while seamlessly integrating with our existing hybrid caching layer.

### v1.2 GitHub Repository Scanning
We expanded CodeShield to accept both local directory paths and remote GitHub URLs. If a remote URL is detected, the FastAPI backend uses Python's built-in 	empfile.TemporaryDirectory() to securely clone the repository. 

To support private repositories, the React frontend passes an optional GitHub Personal Access Token (PAT) which the backend securely injects into the HTTPS clone URL (e.g., \https://<token>@github.com/...\). 

Crucially, because the 	empfile block cleans itself up automatically in the inally clause of the background task, the cloned repository is instantly deleted from disk as soon as the static analyzer and reachability engines finish scanning it. This ensures user hard drives aren't bloated with stale code repositories, since the UI only requires the snippet cached in the SQLite database to display the AI findings.

### v1.3 Automated Code Remediation (Apply Fix)
We upgraded the LangGraph Fixer node to output a strict, machine-readable JSON object containing \patch_target\ and \patch_replacement\ alongside the human-readable explanation. 

This patch data is now saved directly into the SQLite database. If a finding contains a valid code patch, the React dashboard will render an **Apply Fix to File** button inside the AI Triage Details panel. Clicking this button hits a new \POST /apply_fix/{finding_id}\ backend endpoint, which performs a precise string replacement on the local file using Python, automatically securing the application without manual intervention.
