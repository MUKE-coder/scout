// INTENTIONALLY VULNERABLE: reflected XSS. The query is written into the page
// without encoding (dangerouslySetInnerHTML), so markup in ?q= executes.
export default async function Search({ searchParams }) {
  const sp = await searchParams;
  const q = typeof sp.q === "string" ? sp.q : "";
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Search</h1>
      <form className="panel" method="GET">
        <label htmlFor="q">Query</label>
        <input id="q" name="q" defaultValue={q} />
        <button className="btn" style={{ marginTop: 14 }} type="submit">Search</button>
      </form>
      <div className="panel">
        {/* VULN: raw, unescaped reflection of user input */}
        <p>You searched for: <span dangerouslySetInnerHTML={{ __html: q }} /></p>
        <p className="hint">Try <code>{"<img src=x onerror=alert(1)>"}</code> in the query.</p>
      </div>
    </main>
  );
}
