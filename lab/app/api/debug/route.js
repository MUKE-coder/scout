// INTENTIONALLY VULNERABLE: verbose error. Returns a real stack trace to the
// client (information disclosure).
export function GET() {
  try {
    const obj = null;
    return new Response(obj.nope.deep); // throws
  } catch (e) {
    return new Response(`Error: ${e.message}\n${e.stack}`, {
      status: 500,
      headers: { "content-type": "text/plain" },
    });
  }
}
