// INTENTIONALLY VULNERABLE: XXE-style. Reflects entity-looking XML input back,
// simulating a parser that resolves external entities. (Target for an XXE probe.)
export async function POST(req) {
  const body = await req.text().catch(() => "");
  // VULN: a real parser here would resolve <!ENTITY> external entities.
  return new Response(`parsed: ${body}`, { status: 200, headers: { "content-type": "text/plain" } });
}
