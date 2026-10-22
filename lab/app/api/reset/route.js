// INTENTIONALLY VULNERABLE: host-header injection. The password-reset link is
// built from the request Host header, so a spoofed Host poisons the link.
export function GET(req) {
  const host = req.headers.get("host");
  const link = `https://${host}/reset-password?token=abc123`;
  return new Response(`We sent a reset link: ${link}`, {
    status: 200, headers: { "content-type": "text/plain" },
  });
}
