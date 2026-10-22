/**
 * INTENTIONALLY VULNERABLE lab. No security headers are set on purpose, so a
 * scanner sees the misconfigurations. Do NOT copy this config into a real app.
 */
const nextConfig = {
  // Deliberately NOT adding security headers (CSP/HSTS/X-Frame-Options/nosniff).
  reactStrictMode: false,
};
export default nextConfig;
