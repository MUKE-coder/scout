// INTENTIONALLY VULNERABLE: unrestricted file upload. Accepts any file type
// with no validation. (Target for a file-upload probe.)
export async function POST(req) {
  const form = await req.formData().catch(() => null);
  const file = form?.get("file");
  const name = file && typeof file === "object" ? file.name : "none";
  // VULN: no extension/content-type/size checks, "stored" as-is.
  return new Response(JSON.stringify({ stored: name, path: `/uploads/${name}` }), {
    status: 200, headers: { "content-type": "application/json" },
  });
}
