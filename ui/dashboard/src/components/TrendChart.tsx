import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TrendPoint } from "../lib/types";
import { dateTime, shortDate } from "../lib/format";

// 30-day score trend (style guide §5 charts): 1.5px accent line, dashed
// horizontal gridlines only, 12px muted axis labels, no legend.
export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length < 2) {
    return (
      <div className="flex h-40 items-center justify-center text-[13px] text-muted">
        The trend appears after a second scan.
      </div>
    );
  }
  const data = points.map((p) => ({ ...p, t: new Date(p.at).getTime() }));
  return (
    <div className="h-40">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="4 4" />
          <XAxis
            dataKey="t"
            type="number"
            domain={["dataMin", "dataMax"]}
            tickFormatter={(t: number) => shortDate(new Date(t).toISOString())}
            tick={{ fill: "var(--text-muted)", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis domain={[0, 100]} ticks={[0, 50, 100]} tick={{ fill: "var(--text-muted)", fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip
            cursor={{ stroke: "var(--border-strong)" }}
            content={({ active, payload }) => {
              const p = active && payload?.[0]?.payload;
              if (!p) return null;
              return (
                <div className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-[12px]">
                  <div className="text-muted">{dateTime(p.at)}</div>
                  <div className="tabular font-medium">
                    {p.score.toFixed(1)} · Grade {p.grade}
                  </div>
                </div>
              );
            }}
          />
          <Line type="monotone" dataKey="score" stroke="var(--accent)" strokeWidth={1.5} dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
