from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scan
from app.rag_engine import load_cve_data

app = FastAPI(
    title="Vulnerability Scanner API",
    description="AI-powered code security scanner",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)

@app.on_event("startup")
def startup_event():
    load_cve_data()

@app.get("/")
def read_root():
    return {
        "message": "Vulnerability Scanner API is running!",
        "status": "healthy",
        "version": "0.1.0"
    }

@app.get("/health")
def health_check():
    return {"status": "ok"}
