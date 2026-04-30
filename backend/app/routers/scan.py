from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
import os
import uuid
from datetime import datetime
from app.scanner import scan_code
from app.rag_engine import search_similar_cves, generate_ai_explanation
from app.github_connector import parse_github_url, fetch_repo_files, fetch_file_content
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Scan, Vulnerability

router = APIRouter(prefix="/api/scan", tags=["scanning"])

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def save_scan_to_db(db, scan_id, filename, results, vulns):
    db_scan = Scan(
        scan_id=scan_id, filename=filename,
        total_lines=results.get("total_lines", 0),
        risk_score=results.get("risk_score", 0),
        total_vulnerabilities=len(vulns),
        critical_count=results.get("severity_counts", {}).get("CRITICAL", 0),
        high_count=results.get("severity_counts", {}).get("HIGH", 0),
        medium_count=results.get("severity_counts", {}).get("MEDIUM", 0),
        low_count=results.get("severity_counts", {}).get("LOW", 0),
        scan_results=results, analysis_type="ai-powered"
    )
    db.add(db_scan)
    for v in vulns:
        cves = v.get("matched_cves", [])
        db.add(Vulnerability(
            scan_id=scan_id, rule=v.get("rule"), severity=v.get("severity"),
            line_number=v.get("line"), code_snippet=v.get("code"),
            message=v.get("message"), fix=v.get("fix"),
            matched_cve_id=cves[0]["cve_id"] if cves else None,
            matched_cve_title=cves[0]["title"] if cves else None,
            similarity_score=cves[0]["similarity_score"] if cves else None,
            ai_explanation=v.get("ai_explanation")
        ))
    db.commit()


@router.post("/upload")
async def upload_code_file(file: UploadFile = File(...)):
    ALLOWED = {".py", ".js", ".ts", ".java", ".cpp", ".c", ".html", ".css", ".rb", ".go", ".rs", ".php"}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED:
        raise HTTPException(status_code=400, detail=f"File type '{file_ext}' not supported.")
    contents = await file.read()
    scan_id = str(uuid.uuid4())[:8]
    saved_name = f"{scan_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, saved_name)
    with open(file_path, "wb") as f:
        f.write(contents)
    text = contents.decode("utf-8", errors="ignore")
    return {"scan_id": scan_id, "filename": file.filename, "size_bytes": len(contents), "lines": text.count("\n") + 1, "status": "uploaded", "message": f"'{file.filename}' uploaded!", "uploaded_at": datetime.now().isoformat()}


@router.post("/analyze/{scan_id}")
async def analyze_file(scan_id: str):
    files = os.listdir(UPLOAD_DIR)
    target = None
    for f in files:
        if f.startswith(scan_id):
            target = f
            break
    if not target:
        raise HTTPException(status_code=404, detail=f"No file found with scan_id '{scan_id}'")
    with open(os.path.join(UPLOAD_DIR, target), "r") as f:
        code = f.read()
    results = scan_code(code, target)
    results["scan_id"] = scan_id
    return results


@router.post("/analyze-ai/{scan_id}")
async def analyze_with_ai(scan_id: str, db: Session = Depends(get_db)):
    files = os.listdir(UPLOAD_DIR)
    target = None
    for f in files:
        if f.startswith(scan_id):
            target = f
            break
    if not target:
        raise HTTPException(status_code=404, detail=f"No file found with scan_id '{scan_id}'")
    with open(os.path.join(UPLOAD_DIR, target), "r") as f:
        code = f.read()
    basic_results = scan_code(code, target)
    enriched_vulns = []
    for vuln in basic_results["vulnerabilities"]:
        search_text = f"{vuln['rule']}. {vuln['message']} Code: {vuln['code']}"
        cve_matches = search_similar_cves(search_text, top_k=2)
        ai_explanation = generate_ai_explanation(vuln["code"], vuln, cve_matches)
        enriched_vulns.append({**vuln, "matched_cves": cve_matches, "ai_explanation": ai_explanation})
    response = {"scan_id": scan_id, "filename": target, "total_lines": basic_results["total_lines"], "risk_score": basic_results["risk_score"], "severity_counts": basic_results["severity_counts"], "vulnerabilities": enriched_vulns, "analysis_type": "AI-powered (RAG + Groq)"}
    save_scan_to_db(db, scan_id, target, response, enriched_vulns)
    return response


@router.get("/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return {"total_scans": len(scans), "scans": [{"scan_id": s.scan_id, "filename": s.filename, "risk_score": s.risk_score, "total_vulnerabilities": s.total_vulnerabilities, "severity": {"critical": s.critical_count, "high": s.high_count, "medium": s.medium_count, "low": s.low_count}, "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans]}


@router.post("/paste")
async def scan_pasted_code(payload: dict, db: Session = Depends(get_db)):
    code = payload.get("code", "")
    filename = payload.get("filename", "pasted_code.py")
    if not code.strip():
        raise HTTPException(status_code=400, detail="No code provided.")
    results = scan_code(code, filename)
    results["scan_id"] = str(uuid.uuid4())[:8]
    save_scan_to_db(db, results["scan_id"], filename, results, results["vulnerabilities"])
    return results


@router.post("/github")
async def scan_github_repo(payload: dict):
    url = payload.get("url", "")
    parsed = parse_github_url(url)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    owner, repo = parsed["owner"], parsed["repo"]
    repo_info = await fetch_repo_files(owner, repo)
    if "error" in repo_info:
        raise HTTPException(status_code=400, detail=repo_info["error"])
    files_to_scan = repo_info["files"][:15]
    file_reports = []
    total_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for file_info in files_to_scan:
        content = await fetch_file_content(owner, repo, file_info["path"])
        if not content:
            continue
        result = scan_code(content, file_info["path"])
        if result["vulnerabilities"]:
            file_reports.append({"file": file_info["path"], "vulnerabilities": result["vulnerabilities"]})
            for sev in total_severity:
                total_severity[sev] += result["severity_counts"].get(sev, 0)
    return {"owner": owner, "repo": repo, "files_scanned": len(files_to_scan), "risk_score": min(100, total_severity["CRITICAL"]*25 + total_severity["HIGH"]*15 + total_severity["MEDIUM"]*5 + total_severity["LOW"]), "severity_counts": total_severity, "file_reports": file_reports}