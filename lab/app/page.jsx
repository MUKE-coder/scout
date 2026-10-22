const LABS = [
  { slug: "idor", side: "server", title: "IDOR", sub: "Insecure Direct Object Reference", desc: "Read another user's record by changing an id in the request." },
  { slug: "bac", side: "server", title: "Broken Access Control", sub: "Unauthenticated admin area", desc: "Reach an admin dashboard with no authentication at all." },
  { slug: "xss", side: "client", title: "XSS", sub: "Reflected Cross-Site Scripting", desc: "Inject markup that the search page reflects without encoding." },
  { slug: "csrf", side: "client", title: "CSRF", sub: "Cross-Site Request Forgery", desc: "Force a state-changing transfer with no anti-CSRF token." },
  { slug: "jwt", side: "server", title: "JWT alg:none", sub: "Forgeable session token", desc: "The session cookie is an unsigned, never-expiring JWT." },
  { slug: "redirect", side: "server", title: "Open Redirect", sub: "Unvalidated redirect", desc: "Bounce a victim to any external site via a redirect param." },
  { slug: "cors", side: "server", title: "CORS Misconfig", sub: "Reflected origin + credentials", desc: "Any site can read authenticated responses from the API." },
];

const SCOUT_FINDS = [
  "Missing security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy)",
  "Session & CSRF cookies without HttpOnly / Secure / SameSite",
  "Exposed files: /.env, /.env.bak, /.git/config, /backup.sql, /swagger.json, /metrics",
  "Forgeable JWT (alg:none, no expiry) on the session cookie",
  "Permissive CORS (reflects Origin with credentials) at /api/data",
  "Open redirect at /api/redirect",
  "A transfer form with no CSRF token",
  "Committed secrets in .env and an insecure Dockerfile (scan with --repo)",
];

export default function Home() {
  return (
    <main className="container">
      <h1 className="title">Web Hacking Labs</h1>
      <p className="subtitle">Interactive security vulnerability labs — learn by exploiting, and a test target for Scout.</p>
      <div className="filters">
        <span className="badge server">SERVER-SIDE</span>
        <span className="badge client">CLIENT-SIDE</span>
      </div>

      <div className="grid">
        {LABS.map((l) => (
          <div className="card" key={l.slug}>
            <span className={`badge ${l.side}`}>{l.side === "server" ? "SERVER-SIDE" : "CLIENT-SIDE"}</span>
            <h3>{l.title}</h3>
            <p className="sub">{l.sub}</p>
            <p>{l.desc}</p>
            <a className="btn" href={`/labs/${l.slug}`}>Start Lab →</a>
          </div>
        ))}
        <div className="card">
          <span className="badge locked">[CLASSIFIED]</span>
          <h3>[REDACTED]</h3>
          <p className="sub">████████</p>
          <p>This lab is locked. Or is it?</p>
          <a className="btn secondary" href="/api/redirect?url=https://example.com">Probe →</a>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 48 }}>
        <h2>Testing with Scout</h2>
        <p className="hint">Start the lab, then point Scout at it. From the Scout repo root:</p>
        <pre>{`# black-box scan of the running lab
go run ./cmd/scout scan --target http://localhost:4000 --mode active --env dev

# source scan (committed secrets + Dockerfile)
go run ./cmd/scout scan --repo ./lab --mode safe --env dev`}</pre>
        <p className="hint">Scout should surface, among others:</p>
        <ul>
          {SCOUT_FINDS.map((f) => (
            <li key={f} className="hint">{f}</li>
          ))}
        </ul>
      </div>
    </main>
  );
}
