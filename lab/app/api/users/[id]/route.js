// INTENTIONALLY VULNERABLE: IDOR. Returns any user's record by id with no
// ownership or auth check.
const USERS = {
  "1": { id: 1, name: "alice", email: "alice@lab.local", ssn: "111-11-1111", role: "user" },
  "2": { id: 2, name: "bob", email: "bob@lab.local", ssn: "222-22-2222", role: "user" },
  "3": { id: 3, name: "admin", email: "admin@lab.local", ssn: "000-00-0000", role: "admin" },
};
export async function GET(_req, { params }) {
  const { id } = await params;
  const user = USERS[id];
  if (!user) return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  return new Response(JSON.stringify(user), { status: 200, headers: { "content-type": "application/json" } });
}
