export default function CsrfLab() {
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>CSRF</h1>
      <div className="panel">
        <p>The transfer form performs a state-changing POST with no anti-CSRF token, so a malicious page can submit it using the victim's cookies.</p>
        <p><a className="btn" href="/transfer">Open the transfer form →</a></p>
      </div>
    </main>
  );
}
