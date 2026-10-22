import "./globals.css";

export const metadata = {
  title: "Scout Vuln Lab",
  description: "Intentionally vulnerable app for learning and for testing Scout. Localhost only.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <div className="warn">
          ⚠ INTENTIONALLY VULNERABLE — for learning and for testing the Scout scanner. Run on localhost only. Never deploy.
        </div>
        <nav className="nav">
          <a href="/" className="brand">
            SCOUT <span className="accent">&lt;vuln-lab&gt;</span>
          </a>
          <div className="links">
            <a href="/">Labs</a>
            <a href="/admin">Admin</a>
            <a href="/search?q=hello">Search</a>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
