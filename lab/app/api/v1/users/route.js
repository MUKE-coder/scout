// INTENTIONALLY VULNERABLE: a deprecated API version (v1) left running next to
// v2. (Scout's api.improper-asset-mgmt flags the old version.)
export function GET() {
  return new Response(JSON.stringify([{ id: 1, name: "alice", ssn: "111-11-1111" }]), {
    status: 200, headers: { "content-type": "application/json", "x-api-version": "1-deprecated" },
  });
}
