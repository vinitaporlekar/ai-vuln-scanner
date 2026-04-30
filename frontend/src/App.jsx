import { useState, useRef } from "react"

const BASE = "http://localhost:8000"

const SEV = {
  CRITICAL: { bg: "#1a0a0a", border: "#ff2b2b", text: "#ff5555", badge: "#ff2b2b" },
  HIGH: { bg: "#1a1005", border: "#ff8c1a", text: "#ffaa44", badge: "#ff8c1a" },
  MEDIUM: { bg: "#0a1118", border: "#3b8eea", text: "#5aa8ff", badge: "#3b8eea" },
  LOW: { bg: "#0a1210", border: "#2ea87a", text: "#44cc99", badge: "#2ea87a" }
}

function RiskGauge({ score }) {
  const angle = -135 + (score / 100) * 270
  const color = score > 70 ? "#ff2b2b" : score > 40 ? "#ff8c1a" : "#2ea87a"
  return (
    <div style={{ position: "relative", width: 180, height: 180, margin: "0 auto" }}>
      <svg viewBox="0 0 180 180">
        <circle cx="90" cy="90" r="72" fill="none" stroke="#1a1d23"
          strokeWidth="10" strokeDasharray="339.3 113.1"
          strokeDashoffset="-56.5" strokeLinecap="round" />
        <circle cx="90" cy="90" r="72" fill="none" stroke={color}
          strokeWidth="10"
          strokeDasharray={`${score / 100 * 339.3} ${452.4 - score / 100 * 339.3}`}
          strokeDashoffset="-56.5" strokeLinecap="round"
          style={{ transition: "all 1.5s ease", filter: `drop-shadow(0 0 6px ${color}88)` }} />
        <line x1="90" y1="90" x2="90" y2="36" stroke={color}
          strokeWidth="2.5" strokeLinecap="round"
          style={{ transformOrigin: "90px 90px", transform: `rotate(${angle}deg)`,
            transition: "transform 1.5s ease" }} />
        <circle cx="90" cy="90" r="4" fill={color} />
      </svg>
      <div style={{ position: "absolute", bottom: 32, left: 0, right: 0, textAlign: "center" }}>
        <div style={{ fontSize: 36, fontWeight: 800, color, fontFamily: "monospace" }}>{score}</div>
        <div style={{ fontSize: 10, color: "#666b78", letterSpacing: 2 }}>RISK SCORE</div>
      </div>
    </div>
  )
}

function SeverityBar({ counts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  return (
    <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
      {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
        <div key={s} style={{ flex: 1, textAlign: "center" }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: SEV[s].text, fontFamily: "monospace" }}>
            {counts[s]}
          </div>
          <div style={{ fontSize: 9, color: "#555b68", letterSpacing: 1.5 }}>{s}</div>
          <div style={{ height: 3, borderRadius: 2, background: "#1a1d23", marginTop: 6, overflow: "hidden" }}>
            <div style={{ height: "100%", width: total ? `${(counts[s] / total) * 100}%` : 0,
              background: SEV[s].badge, borderRadius: 2, transition: "width 0.8s ease" }} />
          </div>
        </div>
      ))}
    </div>
  )
}

function VulnCard({ vuln, isOpen, toggle, delay }) {
  const s = SEV[vuln.severity]
  return (
    <div onClick={toggle}
      style={{
        background: s.bg, border: `1px solid ${isOpen ? s.border : "#1e2129"}`,
        borderRadius: 10, padding: "14px 18px", cursor: "pointer",
        boxShadow: isOpen ? `0 0 12px ${s.border}22` : "none",
        transition: "all 0.3s ease", marginBottom: 8,
        animation: `fadeSlideIn 0.4s ease ${delay}s both`
      }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ background: s.badge, color: "#0d0f13", fontSize: 10, fontWeight: 800,
            padding: "3px 8px", borderRadius: 4, fontFamily: "monospace" }}>{vuln.severity}</span>
          <span style={{ color: "#c8ccd4", fontSize: 14, fontWeight: 500 }}>{vuln.rule}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ color: "#555b68", fontSize: 12, fontFamily: "monospace" }}>line {vuln.line}</span>
          <span style={{ color: "#555b68", transform: isOpen ? "rotate(180deg)" : "rotate(0)",
            transition: "transform 0.2s" }}>▾</span>
        </div>
      </div>

      <div style={{ marginTop: 8, padding: "6px 10px", background: "#12141a", borderRadius: 6,
        fontFamily: "monospace", fontSize: 12, color: s.text, overflowX: "auto" }}>
        {vuln.code}
      </div>

      {isOpen && (
        <div style={{ marginTop: 14 }}>
          {vuln.matched_cves && vuln.matched_cves[0] && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: "#0d0f13", background: s.text,
                padding: "2px 8px", borderRadius: 4, fontWeight: 700, fontFamily: "monospace" }}>
                {vuln.matched_cves[0].cve_id}
              </span>
              <span style={{ fontSize: 11, color: "#888d9a" }}>{vuln.matched_cves[0].title}</span>
            </div>
          )}

          <div style={{ fontSize: 13, lineHeight: 1.7, color: "#9a9fac", marginBottom: 12, whiteSpace: "pre-wrap" }}>
            {vuln.ai_explanation}
          </div>

          <div style={{ background: "#0d1a12", border: "1px solid #1a3a25", borderRadius: 8, padding: "10px 14px" }}>
            <div style={{ fontSize: 10, color: "#2ea87a", letterSpacing: 1.5, marginBottom: 4, fontWeight: 700 }}>FIX</div>
            <div style={{ fontSize: 12, color: "#44cc99", fontFamily: "monospace", lineHeight: 1.6 }}>{vuln.fix}</div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [view, setView] = useState("upload")
  const [result, setResult] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [scanPhase, setScanPhase] = useState("")
  const [openCards, setOpenCards] = useState({})
  const [dragOver, setDragOver] = useState(false)
  const [fileName, setFileName] = useState("")
  const [error, setError] = useState("")
  const fileRef = useRef(null)

  const handleUpload = async (file) => {
    if (!file) return
    setFileName(file.name)
    setScanning(true)
    setError("")

    try {
      // Step 1: Upload
      setScanPhase("Uploading file...")
      const formData = new FormData()
      formData.append("file", file)
      const uploadRes = await fetch(`${BASE}/api/scan/upload`, { method: "POST", body: formData })
      if (!uploadRes.ok) {
        const err = await uploadRes.json()
        throw new Error(err.detail || "Upload failed")
      }
      const uploadData = await uploadRes.json()

      // Step 2: Analyze with AI
      setScanPhase("Running AI analysis (this takes ~30 seconds)...")
      const analyzeRes = await fetch(`${BASE}/api/scan/analyze-ai/${uploadData.scan_id}`, { method: "POST" })
      if (!analyzeRes.ok) throw new Error("Analysis failed")
      const analyzeData = await analyzeRes.json()

      setResult(analyzeData)
      setView("results")
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files[0]) handleUpload(e.dataTransfer.files[0])
  }

  return (
    <div style={{ minHeight: "100vh", background: "#0d0f13", color: "#c8ccd4",
      fontFamily: "'Segoe UI', system-ui, sans-serif" }}>

      <style>{`
        @keyframes fadeSlideIn { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
        @keyframes pulse { 0%,100% { opacity:0.4; } 50% { opacity:1; } }
        @keyframes scanline { 0% { top:0; } 100% { top:100%; } }
        * { box-sizing:border-box; margin:0; padding:0; }
      `}</style>

      {/* Header */}
      <div style={{ borderBottom: "1px solid #1a1d23", padding: "16px 28px",
        display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #ff2b2b, #ff8c1a)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⛨</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>VulnScanner</div>
            <div style={{ fontSize: 10, color: "#555b68", fontFamily: "monospace", letterSpacing: 1 }}>
              AI-POWERED SECURITY ANALYSIS
            </div>
          </div>
        </div>
        {result && (
          <button onClick={() => { setView("upload"); setResult(null); setOpenCards({}); setFileName(""); setError(""); }}
            style={{ background: "#1a1d23", border: "1px solid #2a2d35", color: "#888d9a",
              padding: "8px 16px", borderRadius: 8, cursor: "pointer", fontSize: 13 }}>
            New scan
          </button>
        )}
      </div>

      <div style={{ maxWidth: 720, margin: "0 auto", padding: "32px 20px" }}>

        {/* UPLOAD VIEW */}
        {view === "upload" && !scanning && (
          <div>
            <div style={{ textAlign: "center", marginBottom: 40 }}>
              <h1 style={{ fontSize: 32, fontWeight: 700, marginBottom: 8, color: "#c8ccd4" }}>
                Scan your code for vulnerabilities
              </h1>
              <p style={{ fontSize: 15, color: "#555b68", maxWidth: 440, margin: "0 auto", lineHeight: 1.6 }}>
                Upload a source file. AI-powered analysis matches against real CVE databases and generates fix recommendations.
              </p>
            </div>

            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              style={{
                border: `2px dashed ${dragOver ? "#ff8c1a" : "#2a2d35"}`,
                borderRadius: 16, padding: "56px 32px", textAlign: "center", cursor: "pointer",
                background: dragOver ? "#1a1508" : "#12141a", transition: "all 0.3s ease"
              }}>
              <input ref={fileRef} type="file"
                accept=".py,.js,.ts,.java,.cpp,.c,.html,.css,.rb,.go,.rs,.php"
                onChange={(e) => handleUpload(e.target.files[0])}
                style={{ display: "none" }} />
              <div style={{ fontSize: 40, marginBottom: 16, opacity: 0.6 }}>↑</div>
              <div style={{ fontSize: 16, fontWeight: 500, color: "#888d9a", marginBottom: 6 }}>
                Drop a code file or click to browse
              </div>
              <div style={{ fontSize: 12, color: "#444855", fontFamily: "monospace" }}>
                .py .js .ts .java .cpp .c .html .css .rb .go .rs .php
              </div>
            </div>

            {error && (
              <div style={{ marginTop: 16, padding: "12px 16px", background: "#1a0a0a",
                border: "1px solid #ff2b2b", borderRadius: 8, color: "#ff5555", fontSize: 13 }}>
                {error}
              </div>
            )}
          </div>
        )}

        {/* SCANNING VIEW */}
        {scanning && (
          <div style={{ textAlign: "center", padding: "80px 0" }}>
            <div style={{ width: 64, height: 64, margin: "0 auto 24px", borderRadius: 16,
              background: "#12141a", border: "1px solid #2a2d35",
              display: "flex", alignItems: "center", justifyContent: "center",
              position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", width: "100%", height: 2,
                background: "linear-gradient(90deg, transparent, #ff8c1a, transparent)",
                animation: "scanline 1.2s linear infinite" }} />
              <span style={{ fontSize: 28, position: "relative", zIndex: 1 }}>⛨</span>
            </div>
            <div style={{ fontSize: 16, fontWeight: 500, marginBottom: 8 }}>
              Analyzing {fileName}...
            </div>
            <div style={{ fontSize: 13, color: "#ff8c1a", fontFamily: "monospace",
              animation: "pulse 1.5s infinite" }}>
              {scanPhase}
            </div>
          </div>
        )}

        {/* RESULTS VIEW */}
        {view === "results" && result && (
          <div>
            <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
              {/* Risk gauge */}
              <div style={{ flex: "1 1 200px", background: "#12141a", borderRadius: 14,
                padding: "20px", border: "1px solid #1a1d23" }}>
                <RiskGauge score={result.risk_score} />
              </div>

              {/* Summary */}
              <div style={{ flex: "1.5 1 300px", background: "#12141a", borderRadius: 14,
                padding: "20px", border: "1px solid #1a1d23" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <div style={{ fontSize: 10, color: "#555b68", letterSpacing: 1.5, fontWeight: 600 }}>FINDINGS</div>
                  <div style={{ fontSize: 11, fontFamily: "monospace", color: "#555b68" }}>{result.filename}</div>
                </div>
                <div style={{ fontSize: 36, fontWeight: 700, fontFamily: "monospace" }}>
                  {result.vulnerabilities.length}
                  <span style={{ fontSize: 14, color: "#555b68", fontWeight: 400, marginLeft: 8 }}>vulnerabilities</span>
                </div>
                <SeverityBar counts={result.severity_counts} />
                <div style={{ marginTop: 12, display: "flex", gap: 16 }}>
                  <div style={{ fontSize: 11, color: "#555b68" }}>
                    <span style={{ fontFamily: "monospace", color: "#888d9a" }}>{result.total_lines}</span> lines
                  </div>
                  <div style={{ fontSize: 11, color: "#555b68" }}>
                    <span style={{ fontFamily: "monospace", color: "#ff8c1a" }}>RAG + AI</span> analysis
                  </div>
                </div>
              </div>
            </div>

            <div style={{ fontSize: 10, color: "#555b68", letterSpacing: 1.5, fontWeight: 600, marginBottom: 10 }}>
              VULNERABILITIES — CLICK TO EXPAND
            </div>

            {result.vulnerabilities
              .sort((a, b) => {
                const o = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
                return o[a.severity] - o[b.severity]
              })
              .map((v, i) => (
                <VulnCard key={i} vuln={v} isOpen={openCards[i]}
                  toggle={() => setOpenCards(prev => ({ ...prev, [i]: !prev[i] }))}
                  delay={i * 0.07} />
              ))
            }

            <div style={{ marginTop: 24, padding: "16px 0", borderTop: "1px solid #1a1d23",
              display: "flex", justifyContent: "space-between" }}>
              <div style={{ fontSize: 11, color: "#444855", fontFamily: "monospace" }}>
                scan_id: {result.scan_id}
              </div>
              <div style={{ fontSize: 11, color: "#444855" }}>
                Powered by ChromaDB + Groq AI
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}