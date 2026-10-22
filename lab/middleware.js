import { NextResponse } from "next/server";

/**
 * INTENTIONALLY VULNERABLE middleware. On purpose it:
 *  - serves files that must never be exposed (.env, .git/config, backups, ...),
 *  - sets a weak session cookie (no HttpOnly/Secure/SameSite) carrying a
 *    forgeable alg:none JWT,
 *  - omits every security header (CSP, HSTS, X-Frame-Options, nosniff, ...).
 * Do NOT copy any of this into a real application.
 */

const b64url = (o) =>
  btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// A JWT with alg:none and no expiry — unsigned and never-expiring on purpose.
const WEAK_JWT = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "1", role: "user" })}.`;

const EXPOSED = {
  "/.env": {
    type: "text/plain",
    body: 'DB_PASSWORD="l4b-prod-db-rotate-me-now-00x"\nJWT_SECRET="l4b-signing-key-do-not-ship-00x"\n',
  },
  "/.env.bak": {
    type: "text/plain",
    body: 'DB_PASSWORD="l4b-prod-db-rotate-me-now-00x"\n',
  },
  "/.git/config": {
    type: "text/plain",
    body: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/secret-internal-app.git\n',
  },
  "/metrics": {
    type: "text/plain",
    body: "# HELP http_requests_total Total requests.\nhttp_requests_total{route=\"/api/users\"} 1337\nprocess_resident_memory_bytes 1.2e8\n",
  },
  "/swagger.json": {
    type: "application/json",
    body: JSON.stringify({ swagger: "2.0", info: { title: "Lab API", version: "0.1" }, paths: { "/api/users/{id}": {} } }),
  },
  "/backup.sql": {
    type: "text/plain",
    body: "-- lab database dump\nINSERT INTO users VALUES (1,'admin','admin@lab.local','adminpass');\n",
  },
};

export function middleware(req) {
  const path = req.nextUrl.pathname;

  const exposed = EXPOSED[path];
  if (exposed) {
    return new NextResponse(exposed.body, { status: 200, headers: { "content-type": exposed.type } });
  }

  const res = NextResponse.next();
  // Weak cookies: no HttpOnly, no Secure, no SameSite. One carries the
  // forgeable JWT. Both are flagged by Scout's cookie-flags and jwt checks.
  res.headers.append("set-cookie", `session=${WEAK_JWT}; Path=/`);
  res.headers.append("set-cookie", `lab_csrf=static-token-123; Path=/`);
  // Deliberately NO security headers are added here.
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
