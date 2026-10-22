"use client";
import { useState } from "react";
export default function IdorLab() {
  const [id, setId] = useState("1");
  const [out, setOut] = useState("");
  async function fetchUser() {
    const r = await fetch(`/api/users/${id}`);
    setOut(JSON.stringify(await r.json(), null, 2));
  }
  return (
    <main className="container">
      <h1 className="title" style={{ fontSize: 30 }}>IDOR</h1>
      <div className="panel">
        <p>The endpoint <code>/api/users/&lt;id&gt;</code> returns any user with no ownership check. Change the id and read someone else's record — including the admin (id 3).</p>
        <label htmlFor="id">User id</label>
        <input id="id" value={id} onChange={(e) => setId(e.target.value)} />
        <button className="btn" style={{ marginTop: 14 }} onClick={fetchUser}>Fetch user</button>
        {out && <div className="result"><pre>{out}</pre></div>}
      </div>
    </main>
  );
}
