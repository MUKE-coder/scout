// INTENTIONALLY VULNERABLE: the form posts a state-changing action with no
// CSRF token, so another site can submit it on a logged-in user's behalf.
export default function Transfer() {
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Transfer funds</h1>
      <form className="panel" method="POST" action="/api/transfer">
        <label htmlFor="to">Recipient</label>
        <input id="to" name="to" defaultValue="bob" />
        <label htmlFor="amount">Amount</label>
        <input id="amount" name="amount" defaultValue="100" />
        {/* VULN: no hidden csrf token field */}
        <button className="btn" style={{ marginTop: 14 }} type="submit">Send</button>
      </form>
      <p className="hint">Scout's crawler flags this form: method POST, no CSRF token.</p>
    </main>
  );
}
