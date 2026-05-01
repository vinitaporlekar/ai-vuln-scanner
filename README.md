
# ⛨ AI Vulnerability Scanner

AI-powered code security scanner that finds vulnerabilities, matches them to real CVEs, and tells you how to fix them.
---

## Quick Start 

### What you need installed first
- Python 3.12+ → [python.org/downloads](https://python.org/downloads)
- Node.js 18+ → [nodejs.org](https://nodejs.org)
- PostgreSQL → `brew install postgresql@17 && brew services start postgresql@17`
- Free Groq API key → [console.groq.com/keys](https://console.groq.com/keys)

### Step 1: Clone and enter the project
```bash
git clone https://github.com/vinitaporlekar/ai-vuln-scanner.git
cd ai-vuln-scanner
```

### Step 2: Set up the backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Create database
```bash
createdb vulnscanner
```

### Step 4: Add your API key
Create a file called `.env` inside the `backend/` folder:## API Endpoints

GROQ_API_KEY=paste_your_key_here

### Step 5: Start the backend
```bash
uvicorn app.main:app --reload
```
Wait until you see `Application startup complete`.

### Step 6: Start the frontend (new terminal)
```bash
cd frontend
npm install
npm run dev
```

### Step 7: Open the app
Go to **http://localhost:5173** — done!

---

## What It Does

Paste code, upload a file, or scan a GitHub repo → finds security issues → matches to real CVEs → AI explains the fix.

### Three ways to scan

| Tab | What it does |
|---|---|
| **Paste code** | Paste code before pushing to GitHub |
| **Upload file** | Drag and drop .py .js .ts .java .cpp etc |
| **GitHub repo** | Paste any public repo URL |

### What it catches

| Issue | Severity | Example |
|---|---|---|
| Hardcoded passwords | Critical | `password = "admin123"` |
| SQL injection | Critical | `"SELECT * WHERE id=" + user_input` |
| Dangerous functions | High | `eval()`, `exec()`, `os.system()` |
| Insecure imports | Medium | `import pickle` |
| Debug leftovers | Low | `print()`, `TODO`, `FIXME` |

---

## How It Works
User pastes code
↓
Scanner checks 5 vulnerability rules
↓
ChromaDB finds matching CVEs (semantic search)
↓
Groq AI writes explanation + fix
↓
React dashboard shows results
↓
PostgreSQL saves scan history

**The AI part (RAG):** Each CVE description is converted to numbers (embeddings) using sentence-transformers. When a vulnerability is found, we search for the most similar CVE by comparing embeddings. Then Groq's Llama 3.3 model reads the code + matched CVE and writes a smart explanation.

---

## Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy
- **AI/ML:** RAG, ChromaDB, Sentence Transformers, Groq (Llama 3.3 70B)
- **Frontend:** React, Vite
- **Database:** PostgreSQL (scan history), ChromaDB (vector search)
- **APIs:** GitHub REST API, Groq API

---

## API Endpoints

| Method | Endpoint | What it does |
|---|---|---|
| POST | `/api/scan/paste` | Scan pasted code |
| POST | `/api/scan/upload` | Upload a file |
| POST | `/api/scan/github` | Scan a GitHub repo |
| POST | `/api/scan/analyze-ai/{id}` | AI-powered analysis |
| GET | `/api/scan/history` | Past scan results |
| GET | `/docs` | Interactive API docs |

---

## Troubleshooting

**`command not found: python`** → Use `python3` instead (Mac)

**`Address already in use`** → `lsof -ti:8000 | xargs kill` then retry

**`ModuleNotFoundError`** → Make sure you're in `backend/` and venv is active: `source venv/bin/activate`

**`CORS error`** → Check `main.py` has `allow_origins=["http://localhost:5173"]`

**`API key invalid`** → Check `.env` file has no quotes: `GROQ_API_KEY=gsk_abc123` not `"gsk_abc123"`

---

## Built By

**Vinita Porlekar** — [GitHub](https://github.com/vinitaporlekar) · [LinkedIn](https://www.linkedin.com/in/vinitaporlekar/)
