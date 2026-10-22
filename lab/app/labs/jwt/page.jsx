"use client";
import { useEffect, useState } from "react";
export default function JwtLab() {
  const [info, setInfo] = useState(null);
  useEffect(() => {
    const m = document.cookie.match(/session=([^;]+)/);
    if (!m) return;
    const parts = m[1].split(".");
    try {
      const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
      const claims = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      setInfo({ token: m[1], header, claims });
    } catch {}
  }, []);
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>JWT alg:none</h1>
      <div className="panel">
        <p>The <code>session</code> cookie is an unsigned, never-expiring JWT. With <code>alg:none</code> anyone can forge it — change <code>role</code> to <code>admin</code> and re-set the cookie.</p>
        {info ? (
          <>
            <label>Header</label><pre>{JSON.stringify(info.header, null, 2)}</pre>
            <label>Claims</label><pre>{JSON.stringify(info.claims, null, 2)}</pre>
            <p className="hint">No signature segment → not verifiable.</p>
          </>
        ) : <p className="hint">Reload the page so the server sets the session cookie.</p>}
      </div>
    </main>
  );
}
