from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import uuid
from datetime import datetime

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