// INTENTIONALLY VULNERABLE: state-changing POST with no CSRF token check.
export async function POST(req) {
  const form = await req.formData().catch(() => null);
  const to = form?.get("to") ?? "unknown";
  const amount = form?.get("amount") ?? "0";
  return new Response(JSON.stringify({ ok: true, transferred: amount, to }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
