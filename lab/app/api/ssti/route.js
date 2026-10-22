// INTENTIONALLY VULNERABLE: server-side template injection. User input is used
// as a template and "evaluated". (Target for an SSTI probe.)
export async function GET(req) {
  const name = new URL(req.url).searchParams.get("name") || "guest";
  // VULN: naive template that evaluates {{ ... }} expressions.
  const tpl = `Hello {{${name}}}`;
  let rendered = tpl;
  try {
    rendered = tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => String(eval(e))); // never do this
  } catch {}
  return new Response(rendered, { status: 200, headers: { "content-type": "text/plain" } });
}
