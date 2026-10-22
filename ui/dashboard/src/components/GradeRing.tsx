import { gradeVar } from "./Severity";

// Grade ring (style guide §5): 160px circle, 8px stroke, track in --border,
// fill in the grade's color, 48px score and letter in the center.
export function GradeRing({ score, grade, size = 160 }: { score: number; grade: string; size?: number }) {
  const stroke = 8;
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const filled = grade ? (Math.max(0, Math.min(100, score)) / 100) * circumference : 0;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={grade ? `Grade ${grade}, score ${score}` : "Not graded"}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={gradeVar(grade)}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dasharray 200ms ease-out" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tabular text-[48px] leading-none font-semibold">{grade ? Math.round(score) : "–"}</span>
        <span className="mt-1 text-[13px] font-medium" style={{ color: gradeVar(grade) }}>
          {grade ? `Grade ${grade}` : "Not graded"}
        </span>
      </div>
    </div>
  );
}
