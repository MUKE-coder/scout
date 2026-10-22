export default function BacLab() {
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>Broken Access Control</h1>
      <div className="panel">
        <p>The admin dashboard has no authentication at all. Just browse to it.</p>
        <p><a className="btn" href="/admin">Open /admin →</a></p>
        <p className="hint">Scout flags unauthenticated admin areas; with scout.Mount + WithRoutes it can flag such a route before even sending a request.</p>
      </div>
    </main>
  );
}
