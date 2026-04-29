from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import uuid
from datetime import datetime
from app.scanner import scan_code  
from app.rag_engine import load_cve_data, search_similar_cves, generate_ai_explanation

# Create a router — a mini-app for scan-related endpoints
router = APIRouter(
    prefix="/api/scan",
    tags=["scanning"]
)

# Folder where uploaded files get saved
UPLOAD_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "uploads"
)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# This endpoint receives a code file from the user
@router.post("/upload")
async def upload_code_file(file: UploadFile = File(...)):
    
    # Only allow code files
    ALLOWED = {
        ".py", ".js", ".ts", ".java", ".cpp",
        ".c", ".html", ".css", ".rb", ".go", ".rs", ".php"
    }
    
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in ALLOWED:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{file_ext}' not supported."
        )
    
    # Read the file contents
    contents = await file.read()
    
    # Give it a unique ID so files don't overwrite each other
    scan_id = str(uuid.uuid4())[:8]
    
    # Save the file
    saved_name = f"{scan_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, saved_name)
    
    with open(file_path, "wb") as f:
        f.write(contents)
    
    # Send back info about what we received
    text = contents.decode("utf-8", errors="ignore")
    return {
        "scan_id": scan_id,
        "filename": file.filename,
        "size_bytes": len(contents),
        "lines": text.count("\n") + 1,
        "status": "uploaded",
        "message": f"'{file.filename}' uploaded! Ready to scan.",
        "uploaded_at": datetime.now().isoformat()
    }

@router.post("/analyze/{scan_id}")
async def analyze_file(scan_id: str):
    """
    Takes a scan_id from a previous upload,
    reads that file, and scans it for vulnerabilities.
    """
    
    # Find the file matching this scan_id
    files = os.listdir(UPLOAD_DIR)
    target = None
    for f in files:
        if f.startswith(scan_id):
            target = f
            break
    
    if not target:
        raise HTTPException(
            status_code=404,
            detail=f"No file found with scan_id '{scan_id}'"
        )
    
    # Read the file
    file_path = os.path.join(UPLOAD_DIR, target)
    with open(file_path, "r") as f:
        code = f.read()
    
    # Run the scanner
    results = scan_code(code, target)
    results["scan_id"] = scan_id
    
    return results

@router.post("/analyze-ai/{scan_id}")
async def analyze_with_ai(scan_id: str):
    """
    The SMART version of analyze.
    Uses RAG to match vulnerabilities with real CVEs
    and generates AI-powered explanations.
    """
    
    # Step 1: Find and read the file (same as before)
    files = os.listdir(UPLOAD_DIR)
    target = None
    for f in files:
        if f.startswith(scan_id):
            target = f
            break
    
    if not target:
        raise HTTPException(
            status_code=404,
            detail=f"No file found with scan_id '{scan_id}'"
        )
    
    file_path = os.path.join(UPLOAD_DIR, target)
    with open(file_path, "r") as f:
        code = f.read()
    
    # Step 2: Run the basic scanner first
    from app.scanner import scan_code
    basic_results = scan_code(code, target)
    
    # Step 3: For each vulnerability found, use RAG
    enriched_vulns = []
    for vuln in basic_results["vulnerabilities"]:
        # Search ChromaDB for similar known CVEs
        search_text = f"{vuln['rule']}. {vuln['message']} Code: {vuln['code']}"
        cve_matches = search_similar_cves(search_text, top_k=2)
        
        # Generate AI explanation
        ai_explanation = generate_ai_explanation(
            vuln["code"], vuln, cve_matches
        )
        
        # Add the RAG results to the vulnerability
        enriched_vulns.append({
            **vuln,  # Keep all original fields
            "matched_cves": cve_matches,
            "ai_explanation": ai_explanation
        })
    
    return {
        "scan_id": scan_id,
        "filename": target,
        "total_lines": basic_results["total_lines"],
        "risk_score": basic_results["risk_score"],
        "severity_counts": basic_results["severity_counts"],
        "vulnerabilities": enriched_vulns,
        "analysis_type": "AI-powered (RAG + Gemini)"
    }