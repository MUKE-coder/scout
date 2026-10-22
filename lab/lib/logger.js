// INTENTIONALLY INSECURE logging (for Scout's code.secret-logging).
export function auditLogin(user, password, token) {
  // VULN: secrets written to logs.
  console.log(`login user=${user} password=${password} token=${token}`);
}
