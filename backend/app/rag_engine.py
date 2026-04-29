# FILE: backend/app/rag_engine.py
# The RAG (Retrieval-Augmented Generation) engine.
# 1. Stores CVE data as embeddings in ChromaDB
# 2. When given a vulnerability, finds the most similar CVEs
# 3. Sends the matches + code to Gemini AI for a smart explanation

import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv
import os
import time

# Load the .env file so we can read GEMINI_API_KEY
load_dotenv()

# ---- STEP 1: Set up the embedding model ----
# This model turns text into numbers (vectors).
# "all-MiniLM-L6-v2" is small, fast, and free.
# It runs LOCALLY on your computer — no API needed.
print("Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")
print("Embedding model loaded!")

# ---- STEP 2: Set up ChromaDB ----
# ChromaDB stores embeddings and lets us search by similarity.
# persist_directory = saves the database to disk so we don't
# have to rebuild it every time we restart the server.
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# A "collection" is like a table in a regular database
collection = chroma_client.get_or_create_collection(
    name="cve_vulnerabilities",
    metadata={"description": "Known CVE vulnerability patterns"}
)

# ---- STEP 3: Set up Groq AI ----
# This is the LLM that writes smart explanations
groq_key = os.getenv("GROQ_API_KEY")
if groq_key:
    groq_client = Groq(api_key=groq_key)
    print("Groq AI configured!")
else:
    groq_client = None
    print("WARNING: No GROQ_API_KEY found. AI explanations disabled.")


def load_cve_data():
    """
    Loads CVE data into ChromaDB.
    Only runs if the database is empty (first time setup).
    """
    from app.cve_data import CVE_DATABASE
    
    # Check if data is already loaded
    if collection.count() >= len(CVE_DATABASE):
        print(f"CVE database already loaded ({collection.count()} entries)")
        return
    
    print("Loading CVE data into ChromaDB...")
    
    # Prepare the data for ChromaDB
    ids = []          # Unique ID for each entry
    documents = []    # The text that gets embedded
    metadatas = []    # Extra info stored alongside
    
    for cve in CVE_DATABASE:
        ids.append(cve["id"])
        # We combine title + description for richer embeddings
        documents.append(f"{cve['title']}. {cve['description']}")
        metadatas.append({
            "title": cve["title"],
            "severity": cve["severity"],
            "fix": cve["fix"],
            "category": cve["category"]
        })
    
    # Generate embeddings and store in ChromaDB
    embeddings = embedder.encode(documents).tolist()
    
    collection.add(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas
    )
    
    print(f"Loaded {len(ids)} CVEs into ChromaDB!")


def search_similar_cves(vulnerability_text: str, top_k: int = 3) -> list:
    """
    Given a vulnerability description, find the most similar 
    CVEs in our database.
    
    Parameters:
        vulnerability_text: description of the found vulnerability
        top_k: how many matches to return (default 3)
    
    Returns:
        List of matching CVEs with similarity scores
    """
    # Turn the query text into an embedding
    query_embedding = embedder.encode([vulnerability_text]).tolist()
    
    # Search ChromaDB for the closest matches
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=top_k
    )
    
    # Format the results nicely
    matches = []
    for i in range(len(results["ids"][0])):
        matches.append({
            "cve_id": results["ids"][0][i],
            "title": results["metadatas"][0][i]["title"],
            "severity": results["metadatas"][0][i]["severity"],
            "fix": results["metadatas"][0][i]["fix"],
            "category": results["metadatas"][0][i]["category"],
            "description": results["documents"][0][i],
            "similarity_score": round(
                1 - results["distances"][0][i], 3
            )
            # ChromaDB returns distance (lower = more similar)
            # We convert to similarity (higher = more similar)
        })
    
    return matches


def generate_ai_explanation(code_snippet: str, vulnerability: dict, 
                            cve_matches: list) -> str:
    """
    Uses Gemini AI to generate a smart, detailed explanation
    of the vulnerability found in the code.
    
    This is the "Generate" part of RAG:
    - Retrieved: CVE matches from ChromaDB
    - Augmented: combined with the actual code
    - Generated: AI writes the explanation
    """
    if not groq_client:
        return "AI explanation unavailable (no API key configured)."
    
    # Build the prompt with all context
    prompt = f"""You are a cybersecurity expert analyzing code for vulnerabilities.

VULNERABLE CODE:
{code_snippet}
DETECTED ISSUE:
- Rule: {vulnerability.get('rule', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Message: {vulnerability.get('message', 'No details')}

SIMILAR KNOWN VULNERABILITIES (from CVE database):
"""
    for match in cve_matches:
        prompt += f"""
- {match['cve_id']}: {match['title']}
  Severity: {match['severity']}
  Description: {match['description'][:200]}
  Recommended Fix: {match['fix']}
"""

    prompt += """
Based on the code and the matching CVE data above, provide:
1. A clear 2-sentence explanation of what's wrong and why it's dangerous
2. The specific CVE(s) this matches and what happened in real-world incidents
3. A concrete code fix (show the corrected code)

Keep the response under 200 words. Be specific to THIS code, not generic."""

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI explanation failed: {str(e)}"