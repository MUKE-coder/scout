// INTENTIONALLY VULNERABLE: business-logic flaw. Accepts negative quantities,
// so the total can be driven below zero (store credit). (Target for a
// business-logic probe.)
export async function POST(req) {
  const { price = 100, quantity = 1 } = await req.json().catch(() => ({}));
  // VULN: no check that quantity > 0.
  const total = price * quantity;
  return new Response(JSON.stringify({ total, refund: total < 0 }), {
    status: 200, headers: { "content-type": "application/json" },
  });
}
