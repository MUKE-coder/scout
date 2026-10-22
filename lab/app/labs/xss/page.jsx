export default function XssLab() {
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Reflected XSS</h1>
      <div className="panel">
        <p>The search page reflects <code>?q=</code> into the HTML without encoding.</p>
        <p><a className="btn" href={"/search?q=" + encodeURIComponent("<img src=x onerror=alert('xss')>")}>Fire the payload →</a></p>
        <p className="hint">Scout's safe-mode canary check detects the unescaped reflection without running script.</p>
      </div>
    </main>
  );
}
