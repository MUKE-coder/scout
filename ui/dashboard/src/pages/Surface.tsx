import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { Network } from "lucide-react";
import { useApi } from "../lib/useApi";
import type { Severity } from "../lib/types";
import { Card, PageTitle, Spinner } from "../components/ui";
import { EmptyState, ErrorNote } from "../components/EmptyState";
import { severityVar } from "../components/Severity";

interface SurfaceNode {
  id: string;
  kind: "domain" | "host" | "service" | "route";
  label: string;
  worst?: Severity;
  open: number;
  children?: SurfaceNode[];
}

// Layout constants: one column per depth, one row per visible leaf.
const COL = 248;
const ROW = 44;
const NODE_W = 200;
const NODE_H = 32;
const PAD = 16;
const COLUMNS = ["Domain", "Host", "Service", "Route"];

interface Placed {
  node: SurfaceNode;
  x: number;
  y: number;
  parent?: Placed;
  collapsed: boolean;
}

// layout places visible nodes: leaves on successive rows, parents centred
// on their children.
function layout(roots: SurfaceNode[], collapsed: Set<string>): { placed: Placed[]; height: number; depth: number } {
  const placed: Placed[] = [];
  let row = 0;
  let maxDepth = 0;
  const visit = (n: SurfaceNode, depth: number, parent?: Placed): Placed => {
    maxDepth = Math.max(maxDepth, depth);
    const isCollapsed = collapsed.has(n.id);
    const p: Placed = { node: n, x: PAD + depth * COL, y: 0, parent, collapsed: isCollapsed };
    placed.push(p);
    const kids = !isCollapsed ? (n.children ?? []) : [];
    if (kids.length === 0) {
      p.y = PAD + row * ROW;
      row++;
    } else {
      const placedKids = kids.map((k) => visit(k, depth + 1, p));
      p.y = (placedKids[0].y + placedKids[placedKids.length - 1].y) / 2;
    }
    return p;
  };
  roots.forEach((r) => visit(r, 0));
  return { placed, height: PAD * 2 + Math.max(row, 1) * ROW, depth: maxDepth + 1 };
}

function truncate(s: string, n = 26) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function Surface() {
  const { data, error, loading } = useApi<{ nodes: SurfaceNode[] }>("/surface");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const navigate = useNavigate();
  const roots = useMemo(() => data?.nodes ?? [], [data]);
  const { placed, height, depth } = useMemo(() => layout(roots, collapsed), [roots, collapsed]);

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote message={error} />;

  function onNode(p: Placed) {
    if (p.node.children?.length) {
      setCollapsed((c) => {
        const next = new Set(c);
        if (next.has(p.node.id)) next.delete(p.node.id);
        else next.add(p.node.id);
        return next;
      });
    } else {
      navigate(`/findings?q=${encodeURIComponent(p.node.label.replace(/^[A-Z]+ /, ""))}`);
    }
  }

  const width = PAD * 2 + (depth - 1) * COL + NODE_W;
  return (
    <>
      <PageTitle>Attack surface</PageTitle>
      {roots.length === 0 ? (
        <EmptyState icon={Network}>The map appears once scans have found hosts, services or routes.</EmptyState>
      ) : (
        <Card className="p-0">
          <div className="flex gap-0 border-b border-border px-4 py-3 text-[11px] font-medium tracking-[0.06em] text-subtle uppercase">
            {COLUMNS.slice(0, depth).map((c) => (
              <span key={c} style={{ width: COL }}>
                {c}
              </span>
            ))}
          </div>
          <div className="overflow-x-auto">
            <svg width={width} height={height} role="img" aria-label="Attack-surface map" className="block">
              {placed
                .filter((p) => p.parent)
                .map((p) => {
                  const x1 = p.parent!.x + NODE_W;
                  const y1 = p.parent!.y + NODE_H / 2;
                  const x2 = p.x;
                  const y2 = p.y + NODE_H / 2;
                  const mx = (x1 + x2) / 2;
                  return <path key={`e-${p.node.id}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="var(--border-strong)" strokeWidth={1} />;
                })}
              {placed.map((p) => {
                const color = p.node.worst ? severityVar[p.node.worst] : "var(--border-strong)";
                const hasKids = !!p.node.children?.length;
                return (
                  <g
                    key={p.node.id}
                    transform={`translate(${p.x},${p.y})`}
                    onClick={() => onNode(p)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onNode(p)}
                    tabIndex={0}
                    role="button"
                    aria-label={`${p.node.kind} ${p.node.label}, ${p.node.open} open findings${hasKids ? (p.collapsed ? ", collapsed" : ", expanded") : ""}`}
                    className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-accent"
                  >
                    <title>{p.node.label}</title>
                    <rect width={NODE_W} height={NODE_H} rx={8} fill="var(--surface)" stroke="var(--border)" />
                    <rect width={3} height={NODE_H - 12} x={0} y={6} rx={1.5} fill={color} />
                    <text x={12} y={NODE_H / 2 + 4} fontSize={12} fill="var(--text)" fontFamily={p.node.kind === "domain" ? "var(--font-sans)" : "var(--font-mono)"}>
                      {truncate(p.node.label)}
                    </text>
                    {p.node.open > 0 && (
                      <text x={NODE_W - (hasKids ? 24 : 10)} y={NODE_H / 2 + 4} fontSize={12} textAnchor="end" fill="var(--text-muted)" className="tabular">
                        {p.node.open}
                      </text>
                    )}
                    {hasKids && (
                      <text x={NODE_W - 10} y={NODE_H / 2 + 4} fontSize={12} textAnchor="end" fill="var(--text-subtle)">
                        {p.collapsed ? "+" : "−"}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </Card>
      )}
    </>
  );
}
