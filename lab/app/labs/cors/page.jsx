"use client";
import { useState } from "react";
export default function CorsLab() {
  const [out, setOut] = useState("");
  async function call() {
    const r = await fetch("/api/data", { credentials: "include" });
    setOut(`ACAO: ${r.headers.get("access-control-allow-origin")}\nACAC: ${r.headers.get("access-control-allow-credentials")}\n\n` + JSON.stringify(await r.json(), null, 2));
  }
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>CORS Misconfig</h1>
      <div className="panel">
        <p><code>/api/data</code> reflects the request Origin and sets <code>Access-Control-Allow-Credentials: true</code>, so any site can read authenticated responses.</p>
        <button className="btn" onClick={call}>Call /api/data</button>
        {out && <div className="result"><pre>{out}</pre></div>}
      </div>
    </main>
  );
}
