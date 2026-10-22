// INTENTIONALLY VULNERABLE: CORS reflects any Origin together with
// credentials, so any site can read authenticated responses.
export function GET(req) {
  const origin = req.headers.get("origin") || "*";
  return new Response(JSON.stringify({ balance: 4200, user: "alice" }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": origin,
      "access-control-allow-credentials": "true",
    },
  });
}
