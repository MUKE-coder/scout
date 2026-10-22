import { useState, type FormEvent } from "react";
import { ApiError, login } from "../lib/api";
import { Button, Input, Label } from "../components/ui";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach Scout.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-border bg-surface p-8">
        <div className="mb-8">
          <div className="text-[22px] font-semibold tracking-tight">Scout</div>
          <p className="mt-1 text-muted">Sign in to see every way in.</p>
        </div>
        <div className="flex flex-col gap-4">
          <div>
            <Label htmlFor="username">Username</Label>
            <Input id="username" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          {error && (
            <p role="alert" className="text-[13px] text-critical">
              {error}
            </p>
          )}
          <Button type="submit" variant="primary" disabled={busy} className="mt-2 w-full">
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </div>
      </form>
    </div>
  );
}
