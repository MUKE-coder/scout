import { useState } from "react";
import { Sparkles } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useApi } from "../lib/useApi";
import { Button, Spinner } from "./ui";

export interface Answer {
  text: string;
  model: string;
  sent: unknown;
}

interface AIStatus {
  enabled: boolean;
  model?: string;
  provider?: string;
}

// useAI reports whether AI explanations are configured on the server.
export function useAI() {
  return useApi<AIStatus>("/ai").data;
}

// AIButton calls an AI endpoint and shows the reply with the exact redacted
// data that was sent. Rendered as plain text: the reply is never parsed as
// HTML or Markdown.
export function AIButton({ path, label }: { path: string; label: string }) {
  const status = useAI();
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!status?.enabled) return null;

  async function ask() {
    setBusy(true);
    setError(null);
    try {
      setAnswer(await api<Answer>(path, { method: "POST" }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "The AI request failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex w-full flex-col gap-3">
      <div>
        <Button onClick={ask} disabled={busy}>
          {busy ? <Spinner size={14} /> : <Sparkles size={16} strokeWidth={1.5} aria-hidden />}
          {label}
        </Button>
      </div>
      {error && <p className="text-[13px] text-critical-fg">{error}</p>}
      {answer && (
        <div className="rounded-lg border border-border bg-surface-2 p-4">
          <div className="mb-2 text-[12px] text-subtle">
            AI answer · {answer.model} via {status.provider ?? "AI Gateway"} · may be wrong; Scout's fix guidance is the source of truth
          </div>
          <div className="text-[14px] leading-relaxed whitespace-pre-wrap">{answer.text}</div>
          <details className="mt-3">
            <summary className="cursor-pointer text-[12px] text-muted">What was sent (redacted)</summary>
            <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-border bg-bg p-3 font-mono text-[12px] whitespace-pre-wrap">
              {JSON.stringify(answer.sent, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}
