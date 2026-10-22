// The current API version.
export function GET() {
  return new Response(JSON.stringify([{ id: 1, name: "alice" }]), {
    status: 200, headers: { "content-type": "application/json", "x-api-version": "2" },
  });
}
