// INTENTIONALLY VULNERABLE: OS command injection. Concatenates user input into
// a shell command. (Target for an active command-injection probe.)
export async function GET(req) {
  const host = new URL(req.url).searchParams.get("host") || "localhost";
  // VULN: never do this — unsanitized input into a shell command.
  const cmd = `ping -c 1 ${host}`;
  return new Response(JSON.stringify({ ran: cmd, note: "a real app would exec() this" }), {
    status: 200, headers: { "content-type": "application/json" },
  });
}
