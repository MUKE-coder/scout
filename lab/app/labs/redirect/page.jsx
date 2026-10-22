"use client";
import { useState } from "react";
export default function RedirectLab() {
  const [url, setUrl] = useState("https://example.com");
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Open Redirect</h1>
      <div className="panel">
        <p><code>/api/redirect?url=</code> sends the browser to any URL with no allowlist — handy for phishing and OAuth bypass.</p>
        <label htmlFor="u">Destination</label>
        <input id="u" value={url} onChange={(e) => setUrl(e.target.value)} />
        <p style={{ marginTop: 14 }}><a className="btn" href={`/api/redirect?url=${encodeURIComponent(url)}`}>Follow redirect →</a></p>
      </div>
    </main>
  );
}
