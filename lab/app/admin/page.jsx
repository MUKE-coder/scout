// INTENTIONALLY VULNERABLE: broken access control. This "admin" area has no
// authentication whatsoever and leaks sensitive fields.
const USERS = [
  { id: 1, name: "alice", email: "alice@lab.local", ssn: "111-11-1111", role: "user" },
  { id: 2, name: "bob", email: "bob@lab.local", ssn: "222-22-2222", role: "user" },
  { id: 3, name: "admin", email: "admin@lab.local", ssn: "000-00-0000", role: "admin" },
];
export default function Admin() {
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Admin dashboard</h1>
      <div className="panel">
        <p className="hint">No login required — that is the bug.</p>
        <pre>{JSON.stringify(USERS, null, 2)}</pre>
      </div>
    </main>
  );
}
