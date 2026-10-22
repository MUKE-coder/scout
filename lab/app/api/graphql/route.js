// INTENTIONALLY VULNERABLE: GraphQL introspection enabled with no auth.
const SCHEMA = {
  data: {
    __schema: {
      queryType: { name: "Query" },
      types: [
        { name: "Query" }, { name: "User" }, { name: "Invoice" }, { name: "AdminSettings" },
      ],
    },
  },
};
export function GET(req) {
  const q = new URL(req.url).searchParams.get("query") || "";
  if (q.includes("__schema")) {
    return new Response(JSON.stringify(SCHEMA), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response(JSON.stringify({ data: {} }), { status: 200, headers: { "content-type": "application/json" } });
}
