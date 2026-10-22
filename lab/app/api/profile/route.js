// INTENTIONALLY VULNERABLE: mass assignment. Binds the whole request body onto
// the user object, so a client can set privileged fields like role/isAdmin.
export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const user = { id: 1, name: "alice", role: "user", isAdmin: false };
  // VULN: blanket merge of client input.
  Object.assign(user, body);
  return new Response(JSON.stringify(user), { status: 200, headers: { "content-type": "application/json" } });
}
