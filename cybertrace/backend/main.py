"""CyberTrace AI Agent: FastAPI application."""
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import agent
import db
import report
import tools as T

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("CYBERTRACE_DATA", BASE / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
for _d in (UPLOAD_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)
db.init_db()

MAX_UPLOAD = 5 * 1024 * 1024
ALLOWED_EXT = {".txt", ".log", ".csv", ".json", ".eml", ".pdf"}
STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
EMAIL_OK = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

app = FastAPI(title="CyberTrace AI Agent", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

_hits = defaultdict(deque)


def rate_limit(key, limit=20, window=60):
    """In-memory sliding window. Use Redis when running multiple workers."""
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests. Slow down.")
    q.append(now)


def _id():
    return uuid.uuid4().hex[:12]


def hash_pw(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def verify_pw(pw, stored):
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 200_000)
    return secrets.compare_digest(dk.hex(), dk_hex)


def _new_session(uid):
    token = secrets.token_urlsafe(32)
    db.run("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)", (token, uid, time.time()))
    return token


def current_user(authorization: str = Header(default="")):
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    row = db.run(
        "SELECT u.user_id, u.name, u.email FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE s.token = ?",
        (token,), "one")
    if not row:
        raise HTTPException(401, "Not authenticated")
    return row


def _get_inv(inv_id, user):
    row = db.run("SELECT * FROM investigations WHERE investigation_id=? AND user_id=?",
                 (inv_id, user["user_id"]), "one")
    if not row:
        raise HTTPException(404, "Investigation not found")
    return row


def _detail(inv_id, user):
    inv = _get_inv(inv_id, user)
    inv["risk"] = json.loads(inv.pop("risk_json") or "null") or {}
    inv["timeline"] = json.loads(inv.pop("timeline_json") or "[]")
    return {
        "investigation": inv,
        "evidence": db.run(
            "SELECT evidence_id, filename, file_type, size, analysis_status, created_at FROM evidence "
            "WHERE investigation_id=? ORDER BY created_at", (inv_id,), "all"),
        "findings": db.run(
            "SELECT * FROM findings WHERE investigation_id=? ORDER BY CASE severity "
            "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
            (inv_id,), "all"),
        "executions": db.run(
            "SELECT tool_name, execution_status, timestamp FROM agent_executions "
            "WHERE investigation_id=? ORDER BY timestamp", (inv_id,), "all"),
        "messages": db.run(
            "SELECT role, content, created_at FROM messages WHERE investigation_id=? ORDER BY created_at",
            (inv_id,), "all"),
        "notes": db.run("SELECT body, created_at FROM notes WHERE investigation_id=? ORDER BY created_at",
                        (inv_id,), "all"),
        "reports": db.run("SELECT report_id, created_at FROM reports WHERE investigation_id=? "
                          "ORDER BY created_at DESC", (inv_id,), "all"),
    }


# ---------- request models ----------

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class InvestigationIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)


class InvestigationPatch(BaseModel):
    status: Optional[str] = None
    title: Optional[str] = Field(default=None, max_length=120)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=200_000)


# ---------- health and auth ----------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "llm": "gemini" if os.getenv("GEMINI_API_KEY") else "offline",
        "threat_intel": "abuseipdb" if os.getenv("ABUSEIPDB_API_KEY") else "local",
    }


@app.post("/api/auth/register")
def register(body: RegisterIn):
    email = body.email.strip().lower()
    if not EMAIL_OK.match(email):
        raise HTTPException(400, "Invalid email address")
    if db.run("SELECT 1 FROM users WHERE email=?", (email,), "one"):
        raise HTTPException(409, "Email already registered")
    uid = uuid.uuid4().hex
    name = body.name.strip()
    db.run("INSERT INTO users (user_id, name, email, password_hash, created_at) VALUES (?,?,?,?,?)",
           (uid, name, email, hash_pw(body.password), time.time()))
    db.audit(uid, "register")
    return {"token": _new_session(uid), "user": {"user_id": uid, "name": name, "email": email}}


@app.post("/api/auth/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    rate_limit("login:" + email, limit=10, window=300)
    u = db.run("SELECT * FROM users WHERE email=?", (email,), "one")
    if not u or not verify_pw(body.password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    db.audit(u["user_id"], "login")
    return {"token": _new_session(u["user_id"]),
            "user": {"user_id": u["user_id"], "name": u["name"], "email": u["email"]}}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


# ---------- investigations ----------

@app.get("/api/investigations")
def list_investigations(user=Depends(current_user)):
    return db.run(
        "SELECT investigation_id, title, status, severity, risk_score, created_at, updated_at "
        "FROM investigations WHERE user_id=? ORDER BY updated_at DESC", (user["user_id"],), "all")


@app.post("/api/investigations")
def create_investigation(body: InvestigationIn, user=Depends(current_user)):
    iid = uuid.uuid4().hex[:12]
    now = time.time()
    db.run(
        "INSERT INTO investigations (investigation_id, user_id, title, description, status, severity, risk_score, "
        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (iid, user["user_id"], body.title.strip(), body.description.strip(), "open", "LOW", 0, now, now))
    db.audit(user["user_id"], "create_investigation", iid)
    return {"investigation_id": iid}


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: str, user=Depends(current_user)):
    return _detail(inv_id, user)


@app.patch("/api/investigations/{inv_id}")
def patch_investigation(inv_id: str, body: InvestigationPatch, user=Depends(current_user)):
    _get_inv(inv_id, user)
    if body.status is not None:
        if body.status not in STATUSES:
            raise HTTPException(400, f"Status must be one of {sorted(STATUSES)}")
        db.run("UPDATE investigations SET status=?, updated_at=? WHERE investigation_id=?",
               (body.status, time.time(), inv_id))
    if body.title:
        db.run("UPDATE investigations SET title=?, updated_at=? WHERE investigation_id=?",
               (body.title.strip(), time.time(), inv_id))
    db.audit(user["user_id"], "update_investigation", inv_id)
    return {"ok": True}


@app.post("/api/investigations/{inv_id}/notes")
def add_note(inv_id: str, body: NoteIn, user=Depends(current_user)):
    _get_inv(inv_id, user)
    db.run("INSERT INTO notes (note_id, investigation_id, body, created_at) VALUES (?,?,?,?)",
           (_id(), inv_id, body.body.strip(), time.time()))
    return {"ok": True}


# ---------- evidence ----------

@app.post("/api/investigations/{inv_id}/evidence")
async def upload_evidence(inv_id: str, file: UploadFile = File(...), user=Depends(current_user)):
    _get_inv(inv_id, user)
    name = file.filename or "evidence"
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXT))}")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "File exceeds the 5 MB limit")
    if not data:
        raise HTTPException(400, "File is empty")

    ev_id = _id()
    safe = SAFE_NAME.sub("_", os.path.basename(name))[:80]
    dest_dir = UPLOAD_DIR / inv_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{ev_id}_{safe}"
    dest.write_bytes(data)  # stored as data only, never executed

    meta = T.file_metadata_analyzer(str(dest), name)
    info = meta.get("data") or {}
    blocked = bool(info.get("blocked"))
    db.run(
        "INSERT INTO evidence (evidence_id, investigation_id, filename, file_type, size, analysis_status, "
        "extracted_information, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (ev_id, inv_id, name, ext, len(data), "blocked" if blocked else "analysed",
         json.dumps({"path": str(dest), "blocked": blocked, "detected_type": info.get("detected_type"),
                     "sha256": info.get("sha256"), "warnings": info.get("warnings", [])}),
         time.time()))
    db.audit(user["user_id"], "upload_evidence", f"{inv_id}:{safe}")
    return {"evidence_id": ev_id, "analysis": info}


# ---------- agent chat ----------

@app.post("/api/investigations/{inv_id}/chat")
def chat(inv_id: str, body: ChatIn, user=Depends(current_user)):
    inv = _get_inv(inv_id, user)
    rate_limit(f"chat:{user['user_id']}", limit=20, window=60)
    db.run("INSERT INTO messages (message_id, investigation_id, role, content, created_at) VALUES (?,?,?,?,?)",
           (_id(), inv_id, "user", body.message, time.time()))

    texts = []
    for ev in db.run("SELECT * FROM evidence WHERE investigation_id=?", (inv_id,), "all"):
        meta = json.loads(ev["extracted_information"] or "{}")
        path = meta.get("path")
        if meta.get("blocked") or not path or not os.path.exists(path):
            continue
        texts.append((ev["filename"], T.extract_text(path, ev["file_type"])))

    result = agent.run_investigation(inv, body.message, texts)
    db.run("INSERT INTO messages (message_id, investigation_id, role, content, created_at) VALUES (?,?,?,?,?)",
           (_id(), inv_id, "assistant", result["reply"], time.time()))
    db.audit(user["user_id"], "agent_run", f"{inv_id} steps={len(result['steps'])}")
    return result


# ---------- reports ----------

@app.post("/api/investigations/{inv_id}/report")
def make_report(inv_id: str, user=Depends(current_user)):
    d = _detail(inv_id, user)
    inv = d["investigation"]
    rid = _id()
    out_dir = REPORT_DIR / inv_id
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{rid}.pdf"
    report.build_pdf(str(path), inv, d["evidence"], d["findings"], d["executions"],
                     inv.get("timeline", []), d["notes"], inv.get("risk", {}))
    db.run("INSERT INTO reports (report_id, investigation_id, report_path, created_at) VALUES (?,?,?,?)",
           (rid, inv_id, str(path), time.time()))
    db.audit(user["user_id"], "generate_report", inv_id)
    return {"report_id": rid}


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: str, user=Depends(current_user)):
    row = db.run(
        "SELECT r.report_path FROM reports r JOIN investigations i ON i.investigation_id = r.investigation_id "
        "WHERE r.report_id=? AND i.user_id=?", (report_id, user["user_id"]), "one")
    if not row or not os.path.exists(row["report_path"]):
        raise HTTPException(404, "Report not found")
    return FileResponse(row["report_path"], media_type="application/pdf",
                        filename=f"cybertrace_{report_id}.pdf")


# ---------- frontend ----------

PWA_FILES = {
    "manifest.json": "application/manifest+json",
    "sw.js": "application/javascript",
    "icon-192.png": "image/png",
    "icon-512.png": "image/png",
}


@app.get("/{name}")
def pwa_asset(name: str):
    if name not in PWA_FILES:
        raise HTTPException(404, "Not found")
    return FileResponse(BASE.parent / "frontend" / name, media_type=PWA_FILES[name],
                        headers={"Cache-Control": "no-cache"})


@app.get("/")
def index():
    return FileResponse(BASE.parent / "frontend" / "index.html", media_type="text/html")
