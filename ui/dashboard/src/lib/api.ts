// Thin API client. The JWT lives in localStorage so a refresh keeps the
// session; storage failures (private windows) only mean logging in again.
const TOKEN_KEY = "scout.token";
export const API = "/scout/api";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* not persisted */
  }
  window.dispatchEvent(new Event("scout:auth"));
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  const res = await fetch(API + path, { ...init, headers });
  if (res.status === 401 && token) setToken(null); // session ended: back to login
  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

// download fetches a file endpoint with the auth header and saves it, so
// protected exports work without exposing the token in a URL.
export async function download(path: string, filename: string) {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(API + path, { headers });
  if (res.status === 401 && token) {
    setToken(null);
    return;
  }
  if (!res.ok) throw new ApiError(res.status, res.statusText);
  // Prefer the server's filename (it prefixes the target host) when present.
  const cd = res.headers.get("Content-Disposition") ?? "";
  const match = cd.match(/filename="?([^"]+)"?/i);
  const name = match?.[1] ?? filename;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function login(username: string, password: string) {
  const res = await api<{ token: string; expires_at: string }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setToken(res.token);
}
