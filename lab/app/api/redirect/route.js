// INTENTIONALLY VULNERABLE: open redirect. Redirects to any user-supplied URL.
export function GET(req) {
  const url = new URL(req.url).searchParams.get("url") || "/";
  return new Response(null, { status: 307, headers: { Location: url } });
}
