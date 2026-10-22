import { useEffect, useState } from "react";
import { getToken } from "./api";

// useAuthed tracks whether a token is present; it updates on login, logout
// and 401s via the scout:auth event, and across tabs via storage events.
export function useAuthed(): boolean {
  const [authed, setAuthed] = useState(() => getToken() !== null);
  useEffect(() => {
    const update = () => setAuthed(getToken() !== null);
    window.addEventListener("scout:auth", update);
    window.addEventListener("storage", update);
    return () => {
      window.removeEventListener("scout:auth", update);
      window.removeEventListener("storage", update);
    };
  }, []);
  return authed;
}
