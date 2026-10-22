// INTENTIONALLY WEAK crypto (for Scout's code.weak-crypto / insecure-random).
import crypto from "crypto";
// VULN: MD5 is broken for security use.
export function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}
// VULN: SHA-1 is broken.
export function fingerprint(s) {
  return crypto.createHash("sha1").update(s).digest("hex");
}
// VULN: Math.random is not cryptographically secure — predictable tokens.
export function resetToken() {
  return Math.random().toString(36).slice(2);
}
