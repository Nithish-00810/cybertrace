# CyberTrace AI Agent

> Think Like an Analyst. Investigate Like an Expert. Defend Like an AI.

A defensive cybersecurity investigation agent. You paste a log, an email, a URL or an IP, or upload evidence. The agent plans an investigation, selects the matching analysis tools, runs them, correlates the results, scores risk, and produces a PDF report that separates **observed evidence** from **rule-based interpretation**.

## What works today

| Area | Status |
|---|---|
| Auth (register, login, bearer sessions, PBKDF2 password hashing) | Working |
| Per-user data isolation (every query is scoped to the owner) | Working |
| Investigations: create, list, open, rename, status, notes, history | Working |
| Evidence upload (TXT, LOG, CSV, JSON, EML, PDF; 5 MB cap; type and signature checks) | Working |
| Log analyzer (JSON, CSV, JSON-lines, syslog/auth.log text) | Working |
| Phishing / email analyzer (urgency, credential requests, header auth, reply-to mismatch, brand impersonation, link text mismatch, risky attachments) | Working |
| URL indicator analyzer (parsed only, never fetched) | Working |
| IP indicator analyzer (classification; AbuseIPDB reputation when keyed) | Working |
| File metadata analyzer (SHA-256, magic-byte type, executable blocking, PDF metadata with PyMuPDF) | Working |
| Event correlator (indicators shared across sources) | Working |
| Risk engine (LOW / MEDIUM / HIGH / CRITICAL, score, confidence, actions) | Working |
| Timeline generator | Working |
| Agent execution log (every tool run is recorded with status) | Working |
| Gemini narration (optional) | Working when `GEMINI_API_KEY` is set; otherwise deterministic offline summary |
| PDF report (ReportLab) | Working |
| SOC-style dashboard (sidebar, chat, right-hand status panel) | Working |
| Rate limiting (chat and login) | Working, in-memory |

## Deliberate differences from the master spec

These were scoped for an MVP you can run and extend. Each is a swap, not a redesign.

- **Frontend:** a single-file HTML/CSS/JS dashboard instead of React + TypeScript + Tailwind + Recharts. No build step. The layout follows the spec, and the component boundaries map cleanly onto React components if you migrate.
- **Database:** SQLite instead of PostgreSQL or Firebase. `db.py` is the only file that talks to the driver. The schema covers every table in the spec.
- **Progress streaming:** the chat endpoint returns the full step list when the run completes. The spec asks for live SSE. The step data is already recorded per tool, so streaming is a small change to the endpoint.
- **Gemini role:** the model narrates tool results but does not choose or execute tools. Tool selection is deterministic and auditable, which is a safer default for a security tool. Tool-calling via Gemini function declarations can be added on top.
- **Approval gate:** the spec requires approval before sensitive actions. The current tools are read-only analysis, so nothing sensitive runs. The approval hook belongs wherever a future action tool (for example, blocking an IP) is added.
- **Threat intel:** only AbuseIPDB is wired up. VirusTotal and similar services follow the same pattern as `_abuseipdb()`.
- **Auth:** email and password only. OAuth and Firebase Auth are straightforward additions.

## Safety rules enforced in code

- Submitted URLs are **parsed, never fetched**. The only outbound network calls are the optional Gemini and AbuseIPDB requests.
- Uploaded files are **stored as data and never executed**. Files with executable signatures (PE, ELF) are flagged `blocked` and excluded from analysis.
- Evidence text, email content and tool output are passed to the LLM as **untrusted data** under a system prompt that forbids following instructions inside them.
- Reports separate `observed` and `intel` findings from `heuristic` ones, and state the limitations.
- Risk scores are labelled as rule matches, not proof of compromise.
- Demo data is labelled `[SAMPLE DATA - NOT LIVE INTELLIGENCE]` and uses RFC 5737 documentation IP addresses.

## Project layout

```
cybertrace/
├── backend/
│   ├── main.py          FastAPI app: auth, investigations, uploads, chat, reports
│   ├── agent.py         Orchestrator: plan, select tools, execute, correlate, score, narrate
│   ├── tools.py         Detection tools (log, URL, IP, email, file, correlator, risk, timeline)
│   ├── report.py        ReportLab PDF generator
│   ├── db.py            SQLite schema and helpers
│   └── requirements.txt
├── frontend/
│   └── index.html       Dashboard (served by the backend at /)
├── .env.example
└── README.md
```

## Run locally

Requires Python 3.10+.

```bash
cd cybertrace/backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional keys
export GEMINI_API_KEY=...        # AI narrative
export ABUSEIPDB_API_KEY=...     # live IP reputation

uvicorn main:app --reload --port 8000
```

Open http://localhost:8000, register, create an investigation, click **Load demo log**, and send. You should see a HIGH-risk result with a success-after-failures finding. Then click **Generate report**.

### Try the detectors from the command line

```bash
cd backend
python -c "import tools as T; print(T.log_analyzer(open('auth.log').read(), 'auth.log')['data']['findings'])"
```

## Deploy

**Single service (simplest):** the backend serves the frontend, so one Render service is enough.

- Root directory: `cybertrace/backend`
- Build: `pip install -r requirements.txt`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Environment: the variables in `.env.example`
- Use a persistent disk and set `CYBERTRACE_DB` and `CYBERTRACE_DATA` to paths on it, or the database and reports are lost on redeploy.

**Split (Vercel frontend + Render backend):** host `frontend/index.html` on Vercel and change the `fetch` base URL to your backend. Set `ALLOWED_ORIGINS` to your Vercel origin.

## Security checklist before a real deployment

- Serve over HTTPS only and set `ALLOWED_ORIGINS` to specific origins.
- Store the session token in an `HttpOnly` cookie instead of `localStorage`, and add CSRF protection if you switch.
- Move rate limiting to Redis if you run more than one worker.
- Add session expiry; sessions currently persist until logout.
- Scan uploads with an AV engine before they are stored, if they come from untrusted users.
- Back up the database and the `data/` directory.

## Limitations

- Log detection depends on recognisable field names and authentication keywords. Unusual formats may be missed. Check the "events parsed" count in the tool output.
- Heuristic rules can produce false positives. For example, the brand-impersonation check does not know every legitimate sender domain. Treat heuristic findings as leads for an analyst.
- The offline summary is deterministic, not conversational. Set `GEMINI_API_KEY` for natural-language answers to open questions.
- PDF text extraction requires PyMuPDF. Without it, PDFs are stored and hashed but their text is not analysed.
